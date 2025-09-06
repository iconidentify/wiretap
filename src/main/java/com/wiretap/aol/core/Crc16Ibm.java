package com.wiretap.aol.core;

public final class Crc16Ibm {
    private Crc16Ibm() {}
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


