package com.wiretap.core;

import com.wiretap.extractor.FrameSummary;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive unit tests for FrameParser.
 * Validates that the consolidated parser behaves identically to the original 5 implementations.
 */
class FrameParserTest {

    // Test data: Real AOL protocol frame with token "At" and streamId 0x2a00
    // Frame structure: [5A][CRC 2B][Len 2B][TX][RX][Type][At][2A00][payload...]
    private static final byte[] SAMPLE_FRAME_AT = new byte[]{
            (byte) 0x5A, 0x01, 0x02, 0x00, 0x06, 0x00, 0x00, 0x20,  // Header (8 bytes)
            0x41, 0x74,                                              // Token "At" (2 bytes)
            0x2A, 0x00,                                              // StreamId 0x2a00 (2 bytes)
            0x00, 0x01, 0x00, 0x00                                   // Payload (4 bytes)
    };

    // Test data: Frame with non-ASCII token
    private static final byte[] SAMPLE_FRAME_HEX_TOKEN = new byte[]{
            (byte) 0x5A, (byte) 0x01, (byte) 0x02, (byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x20,
            (byte) 0xFF, (byte) 0xFE,  // Non-ASCII token
            (byte) 0x00, (byte) 0x01,
            (byte) 0x00, (byte) 0x00
    };

    // Test data: Short frame (9 bytes - special "9B" token)
    private static final byte[] SAMPLE_FRAME_9B = new byte[]{
            (byte) 0x5A, (byte) 0x01, (byte) 0x02, (byte) 0x00, (byte) 0x03, (byte) 0x00, (byte) 0x00, (byte) 0x20, (byte) 0x9B
    };

    @Test
    void testParseBasicFields() {
        Instant now = Instant.now();
        FrameSummary result = FrameParser.parse("C->S", now, SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);

        assertEquals("C->S", result.dir);
        assertNotNull(result.ts);
        assertEquals(6, result.len);  // From bytes [3-4]
        assertEquals("0x20", result.type);  // Byte 7
        assertEquals("0x00", result.tx);    // Byte 5
        assertEquals("0x00", result.rx);    // Byte 6
    }

    @Test
    void testParseExtractsToken() {
        Instant now = Instant.now();
        FrameSummary result = FrameParser.parse("C->S", now, SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);

        assertEquals("At", result.token);  // ASCII token "At"
    }

    @Test
    void testParseExtractsStreamId() {
        Instant now = Instant.now();
        FrameSummary result = FrameParser.parse("C->S", now, SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);

        assertEquals("0x2a00", result.streamId);  // StreamId at bytes 10-11
    }

    @Test
    void testParseNonAsciiToken() {
        Instant now = Instant.now();
        FrameSummary result = FrameParser.parse("S->C", now, SAMPLE_FRAME_HEX_TOKEN, 0, SAMPLE_FRAME_HEX_TOKEN.length);

        assertEquals("0xfffe", result.token);  // Non-ASCII token as hex
    }

    @Test
    void testParse9BFrame() {
        Instant now = Instant.now();
        FrameSummary result = FrameParser.parse("C->S", now, SAMPLE_FRAME_9B, 0, SAMPLE_FRAME_9B.length);

        assertEquals("9B", result.token);
        assertNull(result.streamId);  // Too short for streamId
    }

    @Test
    void testParseGeneratesFullHex() {
        Instant now = Instant.now();
        FrameSummary result = FrameParser.parse("C->S", now, SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);

        assertNotNull(result.fullHex);
        assertTrue(result.fullHex.length() > 0);
        assertTrue(result.fullHex.startsWith("5a"));  // Starts with magic byte
    }

    @Test
    void testParseWithOffset() {
        byte[] buffer = new byte[30];  // Make buffer large enough
        System.arraycopy(SAMPLE_FRAME_AT, 0, buffer, 5, SAMPLE_FRAME_AT.length);

        Instant now = Instant.now();
        FrameSummary result = FrameParser.parse("C->S", now, buffer, 5, SAMPLE_FRAME_AT.length);

        assertEquals("At", result.token);
        assertEquals("0x2a00", result.streamId);
    }

    @Test
    void testParseLiteBasicFields() {
        FrameSummary result = FrameParser.parseLite("S->C", SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);

        assertEquals("S->C", result.dir);
        assertNotNull(result.ts);
        assertEquals(6, result.len);
        assertEquals("0x20", result.type);
    }

    @Test
    void testParseLiteExtractsToken() {
        FrameSummary result = FrameParser.parseLite("C->S", SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);

        assertEquals("At", result.token);
    }

    @Test
    void testParseLiteExtractsStreamId() {
        FrameSummary result = FrameParser.parseLite("C->S", SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);

        assertEquals("0x2a00", result.streamId);
    }

    @Test
    void testParseLiteUsesStringFormat() {
        // Lite version uses String.format for formatting
        FrameSummary result = FrameParser.parseLite("C->S", SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);

        // Type should be formatted with uppercase hex
        assertEquals("0x20", result.type);
        assertTrue(result.type.matches("0x[0-9A-F]{2}"));
    }

    @Test
    void testParseLiteNoPayloadSampling() {
        FrameSummary result = FrameParser.parseLite("C->S", SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);

        // Lite version doesn't extract payload samples
        assertNull(result.payloadHex);
        assertNull(result.payloadText);
        assertNull(result.preview);
    }

    @Test
    void testParseLiteNoCrcValidation() {
        FrameSummary result = FrameParser.parseLite("C->S", SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);

        // Lite version skips CRC validation
        assertNull(result.crcOk);
        assertNull(result.hasError);
        assertNull(result.errorCodes);
    }

    @Test
    void testParseFullDoesPayloadSampling() {
        Instant now = Instant.now();
        FrameSummary result = FrameParser.parse("C->S", now, SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);

        // Full version extracts payload samples
        assertNotNull(result.payloadHex);
        assertNotNull(result.payloadText);
    }

    @Test
    void testParseShortFrame() {
        // Frame too short for complete parsing
        byte[] shortFrame = new byte[]{(byte) 0x5A, 0x01, 0x02};

        Instant now = Instant.now();
        FrameSummary result = FrameParser.parse("C->S", now, shortFrame, 0, shortFrame.length);

        assertNotNull(result);
        assertEquals("C->S", result.dir);
        // Should handle gracefully without crashing
    }

    @Test
    void testParseLiteShortFrame() {
        byte[] shortFrame = new byte[]{(byte) 0x5A, 0x01, 0x02};

        FrameSummary result = FrameParser.parseLite("C->S", shortFrame, 0, shortFrame.length);

        assertNotNull(result);
        assertEquals("C->S", result.dir);
    }

    @Test
    void testParseDirection() {
        Instant now = Instant.now();

        FrameSummary c2s = FrameParser.parse("C->S", now, SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);
        assertEquals("C->S", c2s.dir);

        FrameSummary s2c = FrameParser.parse("S->C", now, SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);
        assertEquals("S->C", s2c.dir);
    }

    @Test
    void testParseLiteTimestampFormat() {
        FrameSummary result = FrameParser.parseLite("C->S", SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);

        assertNotNull(result.ts);
        // Should be a decimal number (epoch seconds with fractional part or E notation)
        assertTrue(result.ts.matches("\\d+\\.\\d+") || result.ts.matches("\\d+\\.\\d+E\\d+"));
    }

    @Test
    void testParseFullTimestampFormat() {
        Instant now = Instant.now();
        FrameSummary result = FrameParser.parse("C->S", now, SAMPLE_FRAME_AT, 0, SAMPLE_FRAME_AT.length);

        assertNotNull(result.ts);
        // Should be formatted with DecimalFormat
        assertTrue(result.ts.contains("."));
    }

    @Test
    void testParseEmptyFrame() {
        byte[] emptyFrame = new byte[0];
        Instant now = Instant.now();

        FrameSummary result = FrameParser.parse("C->S", now, emptyFrame, 0, 0);

        assertNotNull(result);
        assertEquals(0, result.len);
    }
}
