package com.wiretap.core;

import java.security.MessageDigest;

/**
 * Consolidated hex utility functions for WireTap.
 * Replaces duplicated hex methods across AolExtractor, P3Extractor, TcpProxyService, and sniffers.
 */
public final class HexUtil {
    private static final char[] UPPER_HEX = "0123456789ABCDEF".toCharArray();
    private static final char[] LOWER_HEX = "0123456789abcdef".toCharArray();

    private HexUtil() {} // Utility class

    /**
     * Convert bytes to lowercase hex string.
     * @param b byte array
     * @param off starting offset
     * @param len length to convert
     * @return lowercase hex string (e.g., "5a01023f")
     */
    public static String bytesToHexLower(byte[] b, int off, int len) {
        if (len <= 0) return "";
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = off; i < off + len; i++) {
            int v = b[i] & 0xFF;
            sb.append(LOWER_HEX[v >>> 4]).append(LOWER_HEX[v & 0xF]);
        }
        return sb.toString();
    }

    /**
     * Convert entire byte array to uppercase hex string.
     * @param bytes byte array
     * @return uppercase hex string (e.g., "5A01023F")
     */
    public static String bytesToHexUpper(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte x : bytes) {
            int v = x & 0xFF;
            sb.append(UPPER_HEX[v >>> 4]).append(UPPER_HEX[v & 0xF]);
        }
        return sb.toString();
    }

    /**
     * Convert single byte to hex string with "0x" prefix (uppercase).
     * @param b byte value
     * @return hex string (e.g., "0x5A")
     */
    public static String hexByteUpper(int b) {
        char[] out = new char[4];
        out[0] = '0'; out[1] = 'x';
        out[2] = UPPER_HEX[(b >>> 4) & 0xF];
        out[3] = UPPER_HEX[b & 0xF];
        return new String(out);
    }

    /**
     * Convert single byte to lowercase hex string (no prefix).
     * @param b byte value
     * @return hex string (e.g., "5a")
     */
    public static String hexLower(int b) {
        char[] out = new char[2];
        out[0] = LOWER_HEX[(b >>> 4) & 0xF];
        out[1] = LOWER_HEX[b & 0xF];
        return new String(out);
    }

    /**
     * Convert string to printable ASCII, replacing non-printable chars with '.'.
     * @param f byte array
     * @param start starting offset
     * @param end ending offset (exclusive)
     * @return printable string
     */
    public static String printable(byte[] f, int start, int end) {
        StringBuilder sb = new StringBuilder(end - start);
        for (int i = start; i < end; i++) {
            int b = f[i] & 0xFF;
            sb.append(b >= 32 && b < 127 ? (char)b : '.');
        }
        return sb.toString();
    }

    /**
     * Compute SHA-1 hash of hex string.
     * @param hex input hex string
     * @return SHA-1 hash as lowercase hex string
     * @throws Exception if SHA-1 algorithm not available
     */
    public static String sha1Hex(String hex) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(hex.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        byte[] d = md.digest();
        StringBuilder sb = new StringBuilder(d.length * 2);
        for (byte x : d) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }
}
