package com.wiretap.web;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ConnectionInfo class.
 * Tests connection metadata tracking, frame counting, and state management.
 */
class ConnectionInfoTest {

    private ConnectionInfo connection;
    private static final String TEST_CONNECTION_ID = "test-12345";
    private static final String TEST_SOURCE_IP = "192.168.1.100";
    private static final int TEST_SOURCE_PORT = 5190;

    @BeforeEach
    void setUp() {
        connection = new ConnectionInfo(TEST_CONNECTION_ID, TEST_SOURCE_IP, TEST_SOURCE_PORT);
    }

    @Test
    void testConstructor() {
        assertEquals(TEST_CONNECTION_ID, connection.connectionId);
        assertEquals(TEST_SOURCE_IP, connection.sourceIp);
        assertEquals(TEST_SOURCE_PORT, connection.sourcePort);
        assertEquals(0, connection.frameCount);
        assertTrue(connection.active);
        assertNotNull(connection.startTime);
        assertTrue(connection.lastActivityTime > 0);
    }

    @Test
    void testIncrementFrameCount() {
        long initialActivity = connection.lastActivityTime;

        // Small delay to ensure timestamp difference
        try { Thread.sleep(1); } catch (InterruptedException ignored) {}

        connection.incrementFrameCount();

        assertEquals(1, connection.frameCount);
        assertTrue(connection.lastActivityTime > initialActivity);

        connection.incrementFrameCount();
        assertEquals(2, connection.frameCount);
    }

    @Test
    void testMarkClosed() {
        assertTrue(connection.active);

        connection.markClosed();

        assertFalse(connection.active);
    }

    @Test
    void testGetDurationSeconds() {
        // Duration should be very small for a newly created connection
        long duration = connection.getDurationSeconds();
        assertTrue(duration >= 0);
        assertTrue(duration < 5); // Should be less than 5 seconds for a test
    }

    @Test
    void testToJson() {
        connection.incrementFrameCount();
        connection.incrementFrameCount();

        String json = connection.toJson();

        assertNotNull(json);
        assertTrue(json.contains("\"connectionId\":\"" + TEST_CONNECTION_ID + "\""));
        assertTrue(json.contains("\"sourceIp\":\"" + TEST_SOURCE_IP + "\""));
        assertTrue(json.contains("\"sourcePort\":" + TEST_SOURCE_PORT));
        assertTrue(json.contains("\"frameCount\":2"));
        assertTrue(json.contains("\"active\":true"));
        assertTrue(json.contains("\"startTime\":"));
        assertTrue(json.contains("\"durationSeconds\":"));
    }

    @Test
    void testToJsonAfterClosed() {
        connection.markClosed();

        String json = connection.toJson();

        assertTrue(json.contains("\"active\":false"));
    }

    @Test
    void testToString() {
        connection.incrementFrameCount();

        String str = connection.toString();

        assertNotNull(str);
        assertTrue(str.contains(TEST_CONNECTION_ID));
        assertTrue(str.contains(TEST_SOURCE_IP));
        assertTrue(str.contains(String.valueOf(TEST_SOURCE_PORT)));
        assertTrue(str.contains("frames=1"));
        assertTrue(str.contains("active=true"));
    }

    @Test
    void testMultipleFrameIncrements() {
        for (int i = 0; i < 100; i++) {
            connection.incrementFrameCount();
        }

        assertEquals(100, connection.frameCount);
        assertTrue(connection.lastActivityTime > 0);
    }

    @Test
    void testConnectionWithNullValues() {
        // Test edge case with null connection ID (should be handled gracefully)
        ConnectionInfo nullConnection = new ConnectionInfo(null, null, TEST_SOURCE_PORT);

        assertNull(nullConnection.connectionId);
        assertNull(nullConnection.sourceIp);
        assertEquals(TEST_SOURCE_PORT, nullConnection.sourcePort);
        assertEquals(0, nullConnection.frameCount);
        assertTrue(nullConnection.active);
        assertNotNull(nullConnection.startTime);
    }

    @Test
    void testConnectionWithEmptyValues() {
        ConnectionInfo emptyConnection = new ConnectionInfo("", "", 0);

        assertEquals("", emptyConnection.connectionId);
        assertEquals("", emptyConnection.sourceIp);
        assertEquals(0, emptyConnection.sourcePort);
        assertEquals(0, emptyConnection.frameCount);
        assertTrue(emptyConnection.active);
    }
}