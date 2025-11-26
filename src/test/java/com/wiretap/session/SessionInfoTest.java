package com.wiretap.session;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for SessionInfo.
 */
class SessionInfoTest {

    @Test
    @DisplayName("generateId creates unique session IDs")
    void testGenerateId() {
        String id1 = SessionInfo.generateId();
        String id2 = SessionInfo.generateId();

        assertNotNull(id1);
        assertNotNull(id2);
        assertTrue(id1.startsWith("session-"));
        assertTrue(id2.startsWith("session-"));
        // IDs should be unique (different random suffix)
        assertNotEquals(id1, id2);
    }

    @Test
    @DisplayName("New session has correct initial state")
    void testNewSession() {
        String id = SessionInfo.generateId();
        SessionInfo info = new SessionInfo(id);

        assertEquals(id, info.getId());
        assertNotNull(info.getStartTime());
        assertNull(info.getEndTime());
        assertEquals(0, info.getFrameCount());
        assertEquals(0, info.getFileSizeBytes());
        assertTrue(info.isActive());
    }

    @Test
    @DisplayName("incrementFrameCount increments counter")
    void testIncrementFrameCount() {
        SessionInfo info = new SessionInfo("test-session");

        assertEquals(0, info.getFrameCount());
        info.incrementFrameCount();
        assertEquals(1, info.getFrameCount());
        info.incrementFrameCount();
        info.incrementFrameCount();
        assertEquals(3, info.getFrameCount());
    }

    @Test
    @DisplayName("markEnded sets endTime and active=false")
    void testMarkEnded() {
        SessionInfo info = new SessionInfo("test-session");
        assertTrue(info.isActive());
        assertNull(info.getEndTime());

        info.markEnded();

        assertFalse(info.isActive());
        assertNotNull(info.getEndTime());
    }

    @Test
    @DisplayName("getFormattedSize formats bytes correctly")
    void testGetFormattedSize() {
        SessionInfo info = new SessionInfo("test");

        info.setFileSizeBytes(500);
        assertEquals("500 B", info.getFormattedSize());

        info.setFileSizeBytes(1024);
        assertEquals("1.0 KB", info.getFormattedSize());

        info.setFileSizeBytes(1536);
        assertEquals("1.5 KB", info.getFormattedSize());

        info.setFileSizeBytes(1024 * 1024);
        assertEquals("1.0 MB", info.getFormattedSize());

        info.setFileSizeBytes(1024 * 1024 * 1024);
        assertEquals("1.00 GB", info.getFormattedSize());
    }

    @Test
    @DisplayName("getFormattedDuration formats duration correctly")
    void testGetFormattedDuration() {
        // Create session with known start time
        Instant start = Instant.now().minusSeconds(3661); // 1 hour, 1 minute, 1 second ago
        SessionInfo info = new SessionInfo("test", start, null, 0, 0, true);

        String duration = info.getFormattedDuration();
        assertTrue(duration.matches("1:01:0[0-2]"), "Duration should be ~1:01:01, got: " + duration);
    }

    @Test
    @DisplayName("toJson serializes correctly")
    void testToJson() {
        SessionInfo info = new SessionInfo("test-session-123");
        info.incrementFrameCount();
        info.setFileSizeBytes(2048);

        String json = info.toJson();

        assertTrue(json.contains("\"id\":\"test-session-123\""));
        assertTrue(json.contains("\"frameCount\":1"));
        assertTrue(json.contains("\"fileSizeBytes\":2048"));
        assertTrue(json.contains("\"active\":true"));
        assertTrue(json.contains("\"startTime\":"));
    }

    @Test
    @DisplayName("fromJson deserializes correctly")
    void testFromJson() {
        String json = "{\"id\":\"session-20251125-143022-abc123\",\"startTime\":\"2025-11-25T14:30:22Z\"," +
                      "\"frameCount\":1000,\"fileSizeBytes\":51200,\"active\":false}";

        SessionInfo info = SessionInfo.fromJson(json);

        assertEquals("session-20251125-143022-abc123", info.getId());
        assertEquals(1000, info.getFrameCount());
        assertEquals(51200, info.getFileSizeBytes());
        assertFalse(info.isActive());
    }

    @Test
    @DisplayName("Round-trip serialization preserves data")
    void testRoundTrip() {
        SessionInfo original = new SessionInfo("round-trip-test");
        original.incrementFrameCount();
        original.incrementFrameCount();
        original.setFileSizeBytes(12345);

        String json = original.toJson();
        SessionInfo restored = SessionInfo.fromJson(json);

        assertEquals(original.getId(), restored.getId());
        assertEquals(original.getFrameCount(), restored.getFrameCount());
        assertEquals(original.getFileSizeBytes(), restored.getFileSizeBytes());
        assertEquals(original.isActive(), restored.isActive());
    }
}
