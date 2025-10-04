package com.wiretap.core;

/**
 * CRC-16 IBM (Modbus) calculation for AOL protocol frames.
 * Consolidated from com.wiretap.aol.core.Crc16Ibm and com.wiretap.p3.core.Crc16Ibm.
 */
public final class Crc16Ibm {
    private Crc16Ibm() {} // Utility class

    /**
     * Compute CRC-16 IBM checksum over byte range.
     * @param a byte array
     * @param off starting offset
     * @param len length to process
     * @return CRC-16 value (0x0000 - 0xFFFF)
     */
    public static int compute(byte[] a, int off, int len) {
        int crc = 0x0000;
        for (int i = off; i < off + len; i++) {
            crc ^= (a[i] & 0xFF);
            for (int b = 0; b < 8; b++) {
                if ((crc & 0x0001) != 0) {
                    crc = (crc >>> 1) ^ 0xA001;
                } else {
                    crc = (crc >>> 1);
                }
            }
        }
        return crc & 0xFFFF;
    }
}
