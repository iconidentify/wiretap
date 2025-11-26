package com.wiretap.web;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ConnectionRegistry class.
 * Tests connection registration, lifecycle management, and thread safety.
 */
class ConnectionRegistryTest {

    private ConnectionRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new ConnectionRegistry();
    }

    @AfterEach
    void tearDown() {
        if (registry != null) {
            registry.setEnabled(false); // Clean up
        }
    }

    @Test
    void testRegisterConnection() {
        ConnectionInfo connection = registry.registerConnection("conn-1", "192.168.1.100", 5190);

        assertNotNull(connection);
        assertEquals("conn-1", connection.connectionId);
        assertEquals("192.168.1.100", connection.sourceIp);
        assertEquals(5190, connection.sourcePort);
        assertTrue(connection.active);
        assertEquals(0, connection.frameCount);

        // Verify it's stored in registry
        List<ConnectionInfo> connections = registry.getAllConnections();
        assertEquals(1, connections.size());
        assertEquals(connection, connections.get(0));
    }

    @Test
    void testRegisterMultipleConnections() {
        ConnectionInfo conn1 = registry.registerConnection("conn-1", "192.168.1.100", 5190);
        ConnectionInfo conn2 = registry.registerConnection("conn-2", "192.168.1.101", 5191);

        assertNotNull(conn1);
        assertNotNull(conn2);
        assertNotEquals(conn1.connectionId, conn2.connectionId);

        List<ConnectionInfo> connections = registry.getAllConnections();
        assertEquals(2, connections.size());
    }

    @Test
    void testCloseConnection() {
        ConnectionInfo connection = registry.registerConnection("conn-1", "192.168.1.100", 5190);
        assertTrue(connection.active);

        registry.closeConnection("conn-1");

        assertFalse(connection.active);
    }

    @Test
    void testCloseNonExistentConnection() {
        // Should not throw exception
        registry.closeConnection("non-existent");

        // Registry should remain empty
        assertTrue(registry.getAllConnections().isEmpty());
    }

    @Test
    void testRecordFrame() {
        ConnectionInfo connection = registry.registerConnection("conn-1", "192.168.1.100", 5190);
        assertEquals(0, connection.frameCount);

        registry.recordFrame("conn-1");
        assertEquals(1, connection.frameCount);

        registry.recordFrame("conn-1");
        assertEquals(2, connection.frameCount);
    }

    @Test
    void testRecordFrameNonExistentConnection() {
        // Should not throw exception
        registry.recordFrame("non-existent");

        // Registry should remain empty
        assertTrue(registry.getAllConnections().isEmpty());
    }

    @Test
    void testGetActiveConnections() {
        ConnectionInfo conn1 = registry.registerConnection("conn-1", "192.168.1.100", 5190);
        ConnectionInfo conn2 = registry.registerConnection("conn-2", "192.168.1.101", 5191);

        List<ConnectionInfo> activeConnections = registry.getActiveConnections();
        assertEquals(2, activeConnections.size());

        // Close one connection
        registry.closeConnection("conn-1");

        activeConnections = registry.getActiveConnections();
        assertEquals(1, activeConnections.size());
        assertEquals(conn2, activeConnections.get(0));
    }

    @Test
    void testGetConnection() {
        ConnectionInfo connection = registry.registerConnection("conn-1", "192.168.1.100", 5190);

        ConnectionInfo retrieved = registry.getConnection("conn-1");
        assertNotNull(retrieved);
        assertEquals(connection, retrieved);

        ConnectionInfo nonExistent = registry.getConnection("non-existent");
        assertNull(nonExistent);
    }

    @Test
    void testIsConnectionActive() {
        registry.registerConnection("conn-1", "192.168.1.100", 5190);

        assertTrue(registry.isConnectionActive("conn-1"));

        registry.closeConnection("conn-1");
        assertFalse(registry.isConnectionActive("conn-1"));

        assertFalse(registry.isConnectionActive("non-existent"));
    }

    @Test
    void testGetTotalFrameCount() {
        ConnectionInfo conn1 = registry.registerConnection("conn-1", "192.168.1.100", 5190);
        ConnectionInfo conn2 = registry.registerConnection("conn-2", "192.168.1.101", 5191);

        assertEquals(0, registry.getTotalFrameCount());

        registry.recordFrame("conn-1");
        registry.recordFrame("conn-1");
        registry.recordFrame("conn-2");

        assertEquals(3, registry.getTotalFrameCount());
    }

    @Test
    void testReset() {
        registry.registerConnection("conn-1", "192.168.1.100", 5190);
        registry.registerConnection("conn-2", "192.168.1.101", 5191);
        registry.recordFrame("conn-1");

        assertEquals(2, registry.getAllConnections().size());
        assertEquals(1, registry.getTotalFrameCount());

        registry.reset();

        assertTrue(registry.getAllConnections().isEmpty());
        assertEquals(0, registry.getTotalFrameCount());
    }

    @Test
    void testToJson() {
        ConnectionInfo conn1 = registry.registerConnection("conn-1", "192.168.1.100", 5190);
        ConnectionInfo conn2 = registry.registerConnection("conn-2", "192.168.1.101", 5191);
        registry.recordFrame("conn-1");
        registry.closeConnection("conn-2");

        String json = registry.toJson();

        assertNotNull(json);
        assertTrue(json.contains("\"connections\":"));
        assertTrue(json.contains("\"totalConnections\":2"));
        assertTrue(json.contains("\"activeConnections\":1"));
        assertTrue(json.contains("\"totalFrames\":1"));
        assertTrue(json.contains("conn-1"));
        assertTrue(json.contains("192.168.1.100"));
    }

    @Test
    void testToJsonEmpty() {
        String json = registry.toJson();

        assertNotNull(json);
        assertTrue(json.contains("\"connections\":[]"));
        assertTrue(json.contains("\"totalConnections\":0"));
        assertTrue(json.contains("\"activeConnections\":0"));
        assertTrue(json.contains("\"totalFrames\":0"));
    }

    @Test
    void testSetEnabled() {
        assertTrue(registry.isEnabled());

        ConnectionInfo connection = registry.registerConnection("conn-1", "192.168.1.100", 5190);
        assertNotNull(connection);

        registry.setEnabled(false);
        assertFalse(registry.isEnabled());

        // Registry should be cleared when disabled
        assertTrue(registry.getAllConnections().isEmpty());

        // Operations should be no-ops when disabled
        ConnectionInfo nullConnection = registry.registerConnection("conn-2", "192.168.1.101", 5191);
        assertNull(nullConnection);
        assertTrue(registry.getAllConnections().isEmpty());
    }

    @Test
    void testDisabledOperations() {
        registry.setEnabled(false);

        // All operations should be no-ops or return empty results
        assertNull(registry.registerConnection("conn-1", "192.168.1.100", 5190));
        registry.closeConnection("conn-1");
        registry.recordFrame("conn-1");
        registry.reset();

        assertTrue(registry.getAllConnections().isEmpty());
        assertTrue(registry.getActiveConnections().isEmpty());
        assertNull(registry.getConnection("conn-1"));
        assertFalse(registry.isConnectionActive("conn-1"));
        assertEquals(0, registry.getTotalFrameCount());
    }

    @Test
    void testThreadSafety() throws InterruptedException {
        final int threadCount = 10;
        final int operationsPerThread = 100;
        Thread[] threads = new Thread[threadCount];

        // Create threads that register connections and record frames concurrently
        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            threads[i] = new Thread(() -> {
                for (int j = 0; j < operationsPerThread; j++) {
                    String connectionId = "conn-" + threadId + "-" + j;
                    String ip = "192.168.1." + ((threadId * 100 + j) % 255 + 1);
                    int port = 5000 + threadId;

                    registry.registerConnection(connectionId, ip, port);
                    registry.recordFrame(connectionId);

                    if (j % 2 == 0) {
                        registry.closeConnection(connectionId);
                    }
                }
            });
        }

        // Start all threads
        for (Thread thread : threads) {
            thread.start();
        }

        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }

        // Verify final state
        List<ConnectionInfo> connections = registry.getAllConnections();
        assertEquals(threadCount * operationsPerThread, connections.size());

        int expectedTotalFrames = threadCount * operationsPerThread;
        assertEquals(expectedTotalFrames, registry.getTotalFrameCount());

        // Count active vs closed connections
        long activeCount = connections.stream().filter(c -> c.active).count();
        long closedCount = connections.stream().filter(c -> !c.active).count();

        assertEquals(activeCount, registry.getActiveConnections().size());
        assertEquals(activeCount + closedCount, connections.size());
    }
}