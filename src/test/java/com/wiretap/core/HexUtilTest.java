package com.wiretap.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for HexUtil consolidated utility methods.
 */
class HexUtilTest {

    @Test
    void testBytesToHexLower() {
        byte[] data = new byte[]{(byte) 0x5A, 0x01, (byte) 0xFF, 0x00};
        String result = HexUtil.bytesToHexLower(data, 0, data.length);

        assertEquals("5a01ff00", result);
    }

    @Test
    void testBytesToHexLowerWithOffset() {
        byte[] data = new byte[]{0x00, 0x00, (byte) 0x5A, 0x01, (byte) 0xFF};
        String result = HexUtil.bytesToHexLower(data, 2, 3);

        assertEquals("5a01ff", result);
    }

    @Test
    void testBytesToHexLowerEmpty() {
        byte[] data = new byte[0];
        String result = HexUtil.bytesToHexLower(data, 0, 0);

        assertEquals("", result);
    }

    @Test
    void testBytesToHexLowerZeroLength() {
        byte[] data = new byte[]{0x5A, 0x01};
        String result = HexUtil.bytesToHexLower(data, 0, 0);

        assertEquals("", result);
    }

    @Test
    void testBytesToHexUpper() {
        byte[] data = new byte[]{(byte) 0x5A, 0x01, (byte) 0xFF, 0x00};
        String result = HexUtil.bytesToHexUpper(data);

        assertEquals("5A01FF00", result);
    }

    @Test
    void testBytesToHexUpperNull() {
        String result = HexUtil.bytesToHexUpper(null);

        assertEquals("", result);
    }

    @Test
    void testBytesToHexUpperEmpty() {
        byte[] data = new byte[0];
        String result = HexUtil.bytesToHexUpper(data);

        assertEquals("", result);
    }

    @Test
    void testHexByteUpper() {
        String result = HexUtil.hexByteUpper(0x5A);

        assertEquals("0x5A", result);
    }

    @Test
    void testHexByteUpperZero() {
        String result = HexUtil.hexByteUpper(0x00);

        assertEquals("0x00", result);
    }

    @Test
    void testHexByteUpperMax() {
        String result = HexUtil.hexByteUpper(0xFF);

        assertEquals("0xFF", result);
    }

    @Test
    void testHexLower() {
        String result = HexUtil.hexLower(0x5A);

        assertEquals("5a", result);
    }

    @Test
    void testHexLowerZero() {
        String result = HexUtil.hexLower(0x00);

        assertEquals("00", result);
    }

    @Test
    void testHexLowerMax() {
        String result = HexUtil.hexLower(0xFF);

        assertEquals("ff", result);
    }

    @Test
    void testPrintableAscii() {
        byte[] data = new byte[]{'H', 'e', 'l', 'l', 'o'};
        String result = HexUtil.printable(data, 0, data.length);

        assertEquals("Hello", result);
    }

    @Test
    void testPrintableWithNonPrintable() {
        byte[] data = new byte[]{'H', 0x00, 'i', 0x1F, '!'};
        String result = HexUtil.printable(data, 0, data.length);

        assertEquals("H.i.!", result);
    }

    @Test
    void testPrintableWithOffset() {
        byte[] data = new byte[]{0x00, 0x00, 'H', 'i', '!'};
        String result = HexUtil.printable(data, 2, 5);

        assertEquals("Hi!", result);
    }

    @Test
    void testPrintableAllNonPrintable() {
        byte[] data = new byte[]{0x00, 0x01, 0x1F, (byte) 0xFF};
        String result = HexUtil.printable(data, 0, data.length);

        assertEquals("....", result);
    }

    @Test
    void testPrintableEmpty() {
        byte[] data = new byte[0];
        String result = HexUtil.printable(data, 0, 0);

        assertEquals("", result);
    }

    @Test
    void testSha1Hex() throws Exception {
        String input = "5a01ff00";
        String result = HexUtil.sha1Hex(input);

        assertNotNull(result);
        assertEquals(40, result.length());  // SHA-1 produces 40 hex chars
        assertTrue(result.matches("[0-9a-f]{40}"));
    }

    @Test
    void testSha1HexConsistency() throws Exception {
        String input = "test123";
        String result1 = HexUtil.sha1Hex(input);
        String result2 = HexUtil.sha1Hex(input);

        assertEquals(result1, result2);  // Same input = same hash
    }

    @Test
    void testSha1HexDifferentInputs() throws Exception {
        String hash1 = HexUtil.sha1Hex("input1");
        String hash2 = HexUtil.sha1Hex("input2");

        assertNotEquals(hash1, hash2);  // Different inputs = different hashes
    }
}
