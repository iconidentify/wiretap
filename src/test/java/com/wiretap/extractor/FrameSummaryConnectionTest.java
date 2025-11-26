package com.wiretap.extractor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for FrameSummary connection field functionality.
 * Tests the new connectionId, sourceIp, and sourcePort fields.
 */
class FrameSummaryConnectionTest {

    private FrameSummary frame;

    @BeforeEach
    void setUp() {
        frame = new FrameSummary();
        frame.dir = "C->S";
        frame.ts = "1699123456.789";
        frame.token = "At";
        frame.streamId = "0x2a00";
        frame.type = "0x20";
        frame.tx = "0x00";
        frame.rx = "0x00";
        frame.len = 6;
        frame.crcOk = true;
    }

    @Test
    void testConnectionFieldsInJson() {
        frame.connectionId = "test-conn-123";
        frame.sourceIp = "192.168.1.100";
        frame.sourcePort = 5190;

        String json = frame.toJson(false);

        assertNotNull(json);
        assertTrue(json.contains("\"connectionId\":\"test-conn-123\""));
        assertTrue(json.contains("\"sourceIp\":\"192.168.1.100\""));
        assertTrue(json.contains("\"sourcePort\":5190"));
    }

    @Test
    void testConnectionFieldsInPrettyJson() {
        frame.connectionId = "test-conn-456";
        frame.sourceIp = "10.0.0.1";
        frame.sourcePort = 8080;

        String json = frame.toJson(true);

        assertNotNull(json);
        assertTrue(json.contains("\"connectionId\":\"test-conn-456\""));
        assertTrue(json.contains("\"sourceIp\":\"10.0.0.1\""));
        assertTrue(json.contains("\"sourcePort\":8080"));
    }

    @Test
    void testNullConnectionFields() {
        // Connection fields are null by default
        assertNull(frame.connectionId);
        assertNull(frame.sourceIp);
        assertNull(frame.sourcePort);

        String json = frame.toJson(false);

        assertNotNull(json);
        // Null fields should not appear in JSON
        assertFalse(json.contains("connectionId"));
        assertFalse(json.contains("sourceIp"));
        assertFalse(json.contains("sourcePort"));
    }

    @Test
    void testPartialConnectionFields() {
        // Only set some connection fields
        frame.connectionId = "partial-conn";
        frame.sourceIp = "172.16.0.1";
        // sourcePort remains null

        String json = frame.toJson(false);

        assertTrue(json.contains("\"connectionId\":\"partial-conn\""));
        assertTrue(json.contains("\"sourceIp\":\"172.16.0.1\""));
        // Null sourcePort should not appear
        assertFalse(json.contains("sourcePort"));
    }

    @Test
    void testConnectionFieldsWithOtherFields() {
        // Set connection fields along with other optional fields
        frame.connectionId = "full-conn";
        frame.sourceIp = "192.168.1.200";
        frame.sourcePort = 3000;
        frame.fullHex = "5A0102000600002041740000";
        frame.fdoSource = "// Test FDO code";
        frame.hasError = false;

        String json = frame.toJson(false);

        // All fields should be present
        assertTrue(json.contains("\"connectionId\":\"full-conn\""));
        assertTrue(json.contains("\"sourceIp\":\"192.168.1.200\""));
        assertTrue(json.contains("\"sourcePort\":3000"));
        assertTrue(json.contains("\"fullHex\":\"5A0102000600002041740000\""));
        assertTrue(json.contains("\"fdoSource\":\"// Test FDO code\""));
        assertTrue(json.contains("\"hasError\":false"));
    }

    @Test
    void testConnectionFieldsOrdering() {
        frame.connectionId = "order-test";
        frame.sourceIp = "10.1.1.1";
        frame.sourcePort = 443;

        String json = frame.toJson(false);

        // Connection fields should appear after fdoSource field (last in the sequence)
        int fdoIndex = json.indexOf("fdoSource");
        int connIdIndex = json.indexOf("connectionId");
        int sourceIpIndex = json.indexOf("sourceIp");
        int sourcePortIndex = json.indexOf("sourcePort");

        // If fdoSource is present, connection fields should come after it
        // If fdoSource is not present, connection fields should be at the end
        if (fdoIndex != -1) {
            assertTrue(connIdIndex > fdoIndex);
            assertTrue(sourceIpIndex > fdoIndex);
            assertTrue(sourcePortIndex > fdoIndex);
        }

        // Connection fields should maintain their order
        assertTrue(connIdIndex < sourceIpIndex);
        assertTrue(sourceIpIndex < sourcePortIndex);
    }

    @Test
    void testConnectionFieldsWithSpecialCharacters() {
        frame.connectionId = "conn-with-\"quotes\"";
        frame.sourceIp = "192.168.1.100"; // Normal IP

        String json = frame.toJson(false);

        // Special characters should be properly escaped
        assertTrue(json.contains("\"connectionId\":\"conn-with-\\\"quotes\\\"\""));
        assertTrue(json.contains("\"sourceIp\":\"192.168.1.100\""));
    }

    @Test
    void testZeroSourcePort() {
        frame.connectionId = "zero-port-test";
        frame.sourceIp = "127.0.0.1";
        frame.sourcePort = 0;

        String json = frame.toJson(false);

        assertTrue(json.contains("\"connectionId\":\"zero-port-test\""));
        assertTrue(json.contains("\"sourceIp\":\"127.0.0.1\""));
        assertTrue(json.contains("\"sourcePort\":0"));
    }

    @Test
    void testHighPortNumber() {
        frame.connectionId = "high-port-test";
        frame.sourceIp = "192.168.1.1";
        frame.sourcePort = 65535; // Max port number

        String json = frame.toJson(false);

        assertTrue(json.contains("\"sourcePort\":65535"));
    }

    @Test
    void testEmptyConnectionId() {
        frame.connectionId = "";
        frame.sourceIp = "10.0.0.1";
        frame.sourcePort = 1234;

        String json = frame.toJson(false);

        assertTrue(json.contains("\"connectionId\":\"\""));
        assertTrue(json.contains("\"sourceIp\":\"10.0.0.1\""));
        assertTrue(json.contains("\"sourcePort\":1234"));
    }

    @Test
    void testConnectionFieldsBackwardCompatibility() {
        // Test that frames without connection fields still work
        // This simulates existing JSONL files that don't have connection info
        String json = frame.toJson(false);

        // Should contain all the basic fields
        assertTrue(json.contains("\"dir\":\"C->S\""));
        assertTrue(json.contains("\"ts\":\"1699123456.789\""));
        assertTrue(json.contains("\"token\":\"At\""));
        assertTrue(json.contains("\"streamId\":\"0x2a00\""));
        assertTrue(json.contains("\"len\":6"));
        assertTrue(json.contains("\"crcOk\":true"));

        // Should not contain connection fields
        assertFalse(json.contains("connectionId"));
        assertFalse(json.contains("sourceIp"));
        assertFalse(json.contains("sourcePort"));
    }

    @Test
    void testCompleteFrameWithConnectionInfo() {
        // Create a complete frame with all fields including connection info
        frame.connectionId = "complete-test-123";
        frame.sourceIp = "192.168.1.50";
        frame.sourcePort = 12345;
        frame.atoms = "test-atoms";
        frame.preview = "test preview";
        frame.fullHex = "5A01020006000020417400001234";
        frame.ref = "abc123def456";
        frame.payloadHex = "00001234";
        frame.payloadText = "test";
        frame.protocolTag = "AOL";
        frame.hasError = false;

        String json = frame.toJson(false);

        // Verify the JSON is valid and contains all expected fields
        assertNotNull(json);
        assertTrue(json.startsWith("{"));
        assertTrue(json.endsWith("}"));

        // Check connection fields are at the end
        assertTrue(json.contains("\"connectionId\":\"complete-test-123\""));
        assertTrue(json.contains("\"sourceIp\":\"192.168.1.50\""));
        assertTrue(json.contains("\"sourcePort\":12345"));

        // Verify other fields are still present
        assertTrue(json.contains("\"dir\":\"C->S\""));
        assertTrue(json.contains("\"atoms\":\"test-atoms\""));
        assertTrue(json.contains("\"fullHex\":"));
    }
}