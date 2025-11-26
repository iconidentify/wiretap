package com.wiretap.session;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for SessionManager.
 */
class SessionManagerTest {

    @TempDir
    Path tempDir;

    private SessionManager manager;

    @BeforeEach
    void setUp() throws IOException {
        manager = new SessionManager(tempDir);
    }

    @AfterEach
    void tearDown() throws IOException {
        if (manager != null) {
            manager.close();
        }
    }

    @Test
    @DisplayName("startSession creates new session")
    void testStartSession() throws IOException {
        SessionInfo session = manager.startSession();

        assertNotNull(session);
        assertNotNull(session.getId());
        assertTrue(session.isActive());
        assertTrue(manager.hasActiveSession());
        assertSame(session, manager.getCurrentSession());
    }

    @Test
    @DisplayName("stopSession ends current session")
    void testStopSession() throws IOException {
        SessionInfo started = manager.startSession();
        SessionInfo stopped = manager.stopSession();

        assertEquals(started.getId(), stopped.getId());
        assertFalse(stopped.isActive());
        assertFalse(manager.hasActiveSession());
        assertNull(manager.getCurrentSession());
    }

    @Test
    @DisplayName("addFrame writes to current session")
    void testAddFrame() throws IOException {
        manager.startSession();

        assertTrue(manager.addFrame("{\"test\":1}"));
        assertTrue(manager.addFrame("{\"test\":2}"));

        assertEquals(2, manager.getCurrentFrameCount());
    }

    @Test
    @DisplayName("addFrame returns false when no session active")
    void testAddFrameNoSession() {
        assertFalse(manager.addFrame("{\"test\":1}"));
    }

    @Test
    @DisplayName("listSessions returns all sessions")
    void testListSessions() throws IOException, InterruptedException {
        // Create and stop multiple sessions
        SessionInfo s1 = manager.startSession();
        manager.addFrame("{\"session\":1}");
        manager.stopSession();

        // Small delay to ensure different timestamps
        Thread.sleep(10);

        SessionInfo s2 = manager.startSession();
        manager.addFrame("{\"session\":2}");
        manager.stopSession();

        List<SessionInfo> sessions = manager.listSessions();

        assertEquals(2, sessions.size());
        // Should be sorted by start time, most recent first
        assertTrue(sessions.get(0).getStartTime().compareTo(sessions.get(1).getStartTime()) >= 0);
    }

    @Test
    @DisplayName("getSession retrieves session by ID")
    void testGetSession() throws IOException {
        SessionInfo created = manager.startSession();
        manager.addFrame("{\"test\":1}");
        manager.stopSession();

        SessionInfo retrieved = manager.getSession(created.getId());

        assertNotNull(retrieved);
        assertEquals(created.getId(), retrieved.getId());
        assertEquals(1, retrieved.getFrameCount());
    }

    @Test
    @DisplayName("streamSessionFrames outputs all frames")
    void testStreamSessionFrames() throws IOException {
        SessionInfo session = manager.startSession();
        manager.addFrame("{\"frame\":1}");
        manager.addFrame("{\"frame\":2}");
        manager.addFrame("{\"frame\":3}");
        manager.stopSession();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        long count = manager.streamSessionFrames(session.getId(), out, null);

        assertEquals(3, count);
        String output = out.toString(StandardCharsets.UTF_8);
        String[] lines = output.trim().split("\n");
        assertEquals(3, lines.length);
        assertTrue(lines[0].contains("\"frame\":1"));
        assertTrue(lines[1].contains("\"frame\":2"));
        assertTrue(lines[2].contains("\"frame\":3"));
    }

    @Test
    @DisplayName("streamSessionFrames filters by connectionId")
    void testStreamSessionFramesWithFilter() throws IOException {
        SessionInfo session = manager.startSession();
        manager.addFrame("{\"frame\":1,\"connectionId\":\"conn-a\"}");
        manager.addFrame("{\"frame\":2,\"connectionId\":\"conn-b\"}");
        manager.addFrame("{\"frame\":3,\"connectionId\":\"conn-a\"}");
        manager.stopSession();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        long count = manager.streamSessionFrames(session.getId(), out, "conn-a");

        assertEquals(2, count);
        String output = out.toString(StandardCharsets.UTF_8);
        String[] lines = output.trim().split("\n");
        assertEquals(2, lines.length);
        assertTrue(lines[0].contains("conn-a"));
        assertTrue(lines[1].contains("conn-a"));
    }

    @Test
    @DisplayName("deleteSession removes session files")
    void testDeleteSession() throws IOException {
        SessionInfo session = manager.startSession();
        manager.addFrame("{\"test\":1}");
        manager.stopSession();

        String sessionId = session.getId();
        assertTrue(manager.deleteSession(sessionId));

        assertNull(manager.getSession(sessionId));
    }

    @Test
    @DisplayName("deleteSession throws for active session")
    void testDeleteActiveSession() throws IOException {
        SessionInfo session = manager.startSession();

        assertThrows(IOException.class, () -> manager.deleteSession(session.getId()));
    }

    @Test
    @DisplayName("clearAllSessions removes non-active sessions")
    void testClearAllSessions() throws IOException, InterruptedException {
        // Create old sessions
        manager.startSession();
        manager.addFrame("{\"test\":1}");
        manager.stopSession();

        Thread.sleep(10);

        manager.startSession();
        manager.addFrame("{\"test\":2}");
        manager.stopSession();

        Thread.sleep(10);

        // Create active session
        manager.startSession();
        manager.addFrame("{\"test\":3}");

        int deleted = manager.clearAllSessions();

        assertEquals(2, deleted);
        assertEquals(1, manager.listSessions().size()); // Only active session remains
    }

    @Test
    @DisplayName("getTotalDiskUsage returns sum of all session files")
    void testGetTotalDiskUsage() throws IOException {
        manager.startSession();
        for (int i = 0; i < 100; i++) {
            manager.addFrame("{\"data\":\"some test content to create measurable file size " + i + "\"}");
        }
        manager.stopSession();

        long diskUsage = manager.getTotalDiskUsage();
        assertTrue(diskUsage > 0, "Disk usage should be greater than 0");
    }

    @Test
    @DisplayName("findRecoverableSessions returns sessions marked active")
    void testFindRecoverableSessions() throws IOException {
        // Create a session but don't close manager properly
        SessionInfo session = manager.startSession();
        manager.addFrame("{\"test\":1}");
        // Don't call stopSession - simulates crash

        // Create new manager pointing to same directory
        SessionManager newManager = new SessionManager(tempDir);

        List<SessionInfo> recoverable = newManager.findRecoverableSessions();

        assertEquals(1, recoverable.size());
        assertEquals(session.getId(), recoverable.get(0).getId());
        assertTrue(recoverable.get(0).isActive());

        newManager.close();
    }

    @Test
    @DisplayName("recoverSession marks session as ended")
    void testRecoverSession() throws IOException, InterruptedException {
        // Create a session but don't close properly
        SessionInfo session = manager.startSession();
        manager.addFrame("{\"test\":1}");
        manager.addFrame("{\"test\":2}");

        // Force flush the data to disk before "crash"
        Thread.sleep(150); // Wait for scheduled flush (100ms interval)

        // Simulate crash - close manager without proper stopSession
        manager = null;

        // Create new manager and recover
        SessionManager newManager = new SessionManager(tempDir);
        SessionInfo recovered = newManager.recoverSession(session.getId());

        assertNotNull(recovered);
        assertFalse(recovered.isActive());
        // Frame count should be at least 1 (depends on flush timing)
        assertTrue(recovered.getFrameCount() >= 1, "Expected at least 1 frame, got " + recovered.getFrameCount());

        newManager.close();
    }

    @Test
    @DisplayName("getSessionsDirectory returns correct path")
    void testGetSessionsDirectory() {
        assertEquals(tempDir, manager.getSessionsDirectory());
    }

    @Test
    @DisplayName("Starting new session closes previous session")
    void testStartSessionClosePrevious() throws IOException, InterruptedException {
        SessionInfo first = manager.startSession();
        String firstId = first.getId();
        manager.addFrame("{\"session\":1}");

        // Small delay to ensure different session ID
        Thread.sleep(10);

        SessionInfo second = manager.startSession();

        assertNotEquals(firstId, second.getId());
        assertTrue(second.isActive());

        // First session should be closed
        SessionInfo retrievedFirst = manager.getSession(firstId);
        assertNotNull(retrievedFirst);
        assertFalse(retrievedFirst.isActive());
    }
}
