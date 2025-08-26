package com.wiretap.aol.core;

public final class Hex {
    private static final char[] UPPER_HEX = "0123456789ABCDEF".toCharArray();
    private Hex() {}

    public static String bytesToHexLower(byte[] b, int off, int len) {
        if (len <= 0) return "";
        final char[] HEX = "0123456789abcdef".toCharArray();
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = off; i < off + len; i++) {
            int v = b[i] & 0xff;
            sb.append(HEX[v >>> 4]).append(HEX[v & 0xf]);
        }
        return sb.toString();
    }

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte x : bytes) {
            int v = x & 0xFF;
            sb.append(UPPER_HEX[v >>> 4]).append(UPPER_HEX[v & 0x0F]);
        }
        return sb.toString();
    }
}


