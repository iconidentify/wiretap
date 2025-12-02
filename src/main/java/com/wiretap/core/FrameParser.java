package com.wiretap.core;

import com.wiretap.extractor.FrameSummary;

import java.text.DecimalFormat;
import java.time.Instant;

/**
 * Centralized AOL protocol frame parser.
 * Consolidates the 5 duplicated `summarize()` methods from:
 * - AolExtractor.java
 * - P3Extractor.java
 * - TcpProxyService.java
 * - RealtimeAolSniffer.java
 * - RealtimeP3Sniffer.java
 *
 * This is the SINGLE SOURCE OF TRUTH for frame parsing logic.
 */
public final class FrameParser {
    private static final int AOL_MAGIC = 0x5A;
    private static final DecimalFormat TS_FMT = new DecimalFormat("0.000000");

    // P3 packet type constants
    private static final int P3_DATA   = 0x20;
    private static final int P3_INIT   = 0x23;
    private static final int P3_ACK    = 0x24;
    private static final int P3_NAK    = 0x25;
    private static final int P3_HBEAT  = 0x26;
    private static final int P3_RESET  = 0x28;
    private static final int P3_RAK    = 0x29;
    private static final int P3_SETUP  = 0x2A;
    private static final int P3_ACKNOW = 0x2B;

    // NAK error code constants (data[0] in NAK packets)
    private static final int NAK_CRC_ERROR         = 0x01;
    private static final int NAK_SEQUENCE_ERROR    = 0x02;
    private static final int NAK_LENGTH_ERROR      = 0x03;
    private static final int NAK_PACKET_BUILD_ERROR = 0x04;

    private FrameParser() {} // Utility class

    /**
     * Get human-readable P3 packet type name from type byte.
     * Masks off the direction bit (0x80) to get base type.
     */
    private static String getP3TypeName(int type) {
        int baseType = type & 0x7F;  // Mask off direction bit
        switch (baseType) {
            case P3_DATA:   return "DATA";
            case P3_INIT:   return "INIT";
            case P3_ACK:    return "ACK";
            case P3_NAK:    return "NAK";
            case P3_HBEAT:  return "HBEAT";
            case P3_RESET:  return "RESET";
            case P3_RAK:    return "RAK";
            case P3_SETUP:  return "SETUP";
            case P3_ACKNOW: return "ACKNOW";
            default:        return null;  // Unknown type
        }
    }

    /**
     * Check if this is a DATA packet (has token/streamId payload).
     */
    private static boolean isDataPacket(int type) {
        return (type & 0x7F) == P3_DATA;
    }

    /**
     * Check if this is a NAK packet.
     */
    private static boolean isNakPacket(int type) {
        return (type & 0x7F) == P3_NAK;
    }

    /**
     * Get human-readable NAK error reason from error code byte.
     */
    private static String getNakReason(int errorCode) {
        switch (errorCode) {
            case NAK_CRC_ERROR:          return "CRC_ERROR";
            case NAK_SEQUENCE_ERROR:     return "SEQUENCE_ERROR";
            case NAK_LENGTH_ERROR:       return "LENGTH_ERROR";
            case NAK_PACKET_BUILD_ERROR: return "PACKET_BUILD_ERROR";
            default:                     return "UNKNOWN_0x" + Integer.toHexString(errorCode);
        }
    }

    /**
     * Parse AOL frame with full analysis (for PCAP extractors).
     * Includes CRC validation, payload sampling, and error detection.
     *
     * @param dir direction ("C->S" or "S->C")
     * @param ts timestamp
     * @param f frame bytes
     * @param off offset in byte array
     * @param length frame length
     * @return FrameSummary with complete analysis
     */
    public static FrameSummary parse(String dir, Instant ts, byte[] f, int off, int length) {
        FrameSummary s = new FrameSummary();
        s.dir = dir;
        s.ts = TS_FMT.format(ts.getEpochSecond() + (ts.getNano() / 1_000_000_000.0));

        // Extract header fields
        s.len = length >= 6 ? (((f[off+3] & 0xFF) << 8) | (f[off+4] & 0xFF)) : 0;
        int typeByte = length > 7 ? (f[off+7] & 0xFF) : 0;
        s.type = length > 7 ? HexUtil.hexByteUpper(typeByte) : "n/a";
        s.typeName = length > 7 ? getP3TypeName(typeByte) : null;
        s.tx = length > 5 ? String.valueOf(f[off+5] & 0xFF) : "n/a";
        s.rx = length > 6 ? String.valueOf(f[off+6] & 0xFF) : "n/a";

        // Extract token and streamId (only for DATA packets - control packets have no payload)
        boolean isData = length > 7 && isDataPacket(typeByte);
        if (isData && length >= 10 && (f[off] & 0xFF) == AOL_MAGIC) {
            char c1 = (char)(f[off+8] & 0xFF), c2 = (char)(f[off+9] & 0xFF);
            if (c1 >= 32 && c1 < 127 && c2 >= 32 && c2 < 127) {
                s.token = "" + c1 + c2;
            } else {
                s.token = "0x" + HexUtil.hexLower(f[off+8] & 0xFF) + HexUtil.hexLower(f[off+9] & 0xFF);
            }

            // Extract streamId (2 bytes after token at offset 10-11)
            if (length >= 12) {
                s.streamId = "0x" + HexUtil.hexLower(f[off+10] & 0xFF) + HexUtil.hexLower(f[off+11] & 0xFF);
            }
        }
        // Note: Control packets (ACK, NAK, HBEAT, etc.) have no token/streamId - leave them null

        // Extract NAK error code (data[0] in NAK packets)
        if (isNakPacket(typeByte) && length > 8) {
            int nakErrorCode = f[off+8] & 0xFF;
            s.nakReason = getNakReason(nakErrorCode);
        }

        // CRC validation
        if (length >= 5) {
            int hdrBE = ((f[off+1] & 0xFF) << 8) | (f[off+2] & 0xFF);
            int hdrLE = ((f[off+2] & 0xFF) << 8) | (f[off+1] & 0xFF);
            // Variant A: bytes [len_hi .. end-2] (legacy)
            int calcA = Crc16Ibm.compute(f, off + 3, length - 4);
            // Variant B: bytes [tx .. end-2] (skip len); often used when len includes tx/rx/type/token
            int calcB = length > 6 ? Crc16Ibm.compute(f, off + 5, length - 6) : calcA;
            boolean ok = (calcA == hdrBE) || (calcA == hdrLE) || (calcB == hdrBE) || (calcB == hdrLE);
            s.crcOk = ok;
            if (!ok) {
                s.hasError = true;
                s.errorCodes = s.errorCodes == null ? "CRC" : s.errorCodes + ",CRC";
            }
        }

        s.fullHex = HexUtil.bytesToHexLower(f, off, length);

        // Payload sampling for UI enrichment
        if (length > 6) {
            int payStart = off + 6;
            int payLen = Math.max(0, length - 6);
            int sample = Math.min(payLen, 256);
            if (sample > 0) {
                s.payloadHex = HexUtil.bytesToHexLower(f, payStart, sample);
                s.payloadText = HexUtil.printable(f, payStart, payStart + Math.min(sample, 96));
            }
            // legacy preview: keep short printable for AT frames
            if (length >= 12 && "AT".equals(s.token)) {
                int payEnd = Math.min(off + length, payStart + 64);
                s.preview = HexUtil.printable(f, payStart, payEnd);
            }
        }

        return s;
    }

    /**
     * Parse AOL frame with lite analysis (for real-time proxy/sniffers).
     * Skips CRC validation and payload sampling for better performance.
     *
     * @param dir direction ("C->S" or "S->C")
     * @param f frame bytes
     * @param off offset in byte array
     * @param length frame length
     * @return FrameSummary with basic fields
     */
    public static FrameSummary parseLite(String dir, byte[] f, int off, int length) {
        FrameSummary s = new FrameSummary();
        s.dir = dir;
        s.ts = String.valueOf(System.currentTimeMillis() / 1000.0);

        // Extract header fields
        s.len = length >= 6 ? (((f[off+3] & 0xFF) << 8) | (f[off+4] & 0xFF)) : 0;
        int typeByte = length > 7 ? (f[off+7] & 0xFF) : 0;
        s.type = length > 7 ? String.format("0x%02X", typeByte) : "n/a";
        s.typeName = length > 7 ? getP3TypeName(typeByte) : null;
        s.tx = length > 5 ? String.valueOf(f[off+5] & 0xFF) : "n/a";
        s.rx = length > 6 ? String.valueOf(f[off+6] & 0xFF) : "n/a";

        // Extract token and streamId (only for DATA packets - control packets have no payload)
        boolean isData = length > 7 && isDataPacket(typeByte);
        if (isData && length >= 10 && (f[off] & 0xFF) == AOL_MAGIC) {
            char c1 = (char)(f[off+8] & 0xFF), c2 = (char)(f[off+9] & 0xFF);
            if (c1 >= 32 && c1 < 127 && c2 >= 32 && c2 < 127) {
                s.token = "" + c1 + c2;
            } else {
                s.token = String.format("0x%02x%02x", f[off+8] & 0xFF, f[off+9] & 0xFF);
            }

            // Extract streamId (2 bytes after token at offset 10-11)
            if (length >= 12) {
                s.streamId = String.format("0x%02x%02x", f[off+10] & 0xFF, f[off+11] & 0xFF);
            }
        }
        // Note: Control packets (ACK, NAK, HBEAT, etc.) have no token/streamId - leave them null

        // Extract NAK error code (data[0] in NAK packets)
        if (isNakPacket(typeByte) && length > 8) {
            int nakErrorCode = f[off+8] & 0xFF;
            s.nakReason = getNakReason(nakErrorCode);
        }

        s.fullHex = HexUtil.bytesToHexLower(f, off, length);

        return s;
    }
}
