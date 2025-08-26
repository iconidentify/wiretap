package com.wiretap.aol.extractor;

import java.time.Instant;

public final class EthernetDecoder implements LinkDecoder {

    private static int ipOffsetFor(int linkType, byte[] p) {
        return switch (linkType) {
            case 0 -> 4;
            case 1 -> 14;
            case 101, 228, 229 -> 0;
            case 113 -> 16;
            case 276 -> 20;
            default -> -1;
        };
    }

    @Override
    public Segment decode(int linkType, Instant ts, byte[] bytes, int serverPort) {
        int ipOff = ipOffsetFor(linkType, bytes);
        if (ipOff < 0 || bytes.length <= ipOff) return null;
        int ipVer = (bytes[ipOff] >> 4) & 0xF;
        if (ipVer == 4) {
            int ihl = (bytes[ipOff] & 0x0F) * 4;
            if (bytes.length < ipOff + ihl + 20) return null;
            int proto = bytes[ipOff + 9] & 0xFF;
            if (proto != 6) return null;
            int tcpOff = ipOff + ihl;
            int srcPort = ((bytes[tcpOff] & 0xFF) << 8) | (bytes[tcpOff + 1] & 0xFF);
            int dstPort = ((bytes[tcpOff + 2] & 0xFF) << 8) | (bytes[tcpOff + 3] & 0xFF);
            if (srcPort != serverPort && dstPort != serverPort) return null;
            int doff = ((bytes[tcpOff + 12] >> 4) & 0xF) * 4;
            int payloadOff = tcpOff + doff;
            int payloadLen = Math.max(0, bytes.length - payloadOff);
            long seq = ((long)(bytes[tcpOff + 4] & 0xFF) << 24) |
                       ((long)(bytes[tcpOff + 5] & 0xFF) << 16) |
                       ((long)(bytes[tcpOff + 6] & 0xFF) << 8) |
                       ((long)(bytes[tcpOff + 7] & 0xFF));
            String dir = (dstPort == serverPort) ? "C->S" : "S->C";
            return new Segment(dir, ts, srcPort, dstPort, seq, bytes, payloadOff, payloadLen);
        } else if (ipVer == 6) {
            if (bytes.length < ipOff + 40 + 20) return null;
            int nextHdr = bytes[ipOff + 6] & 0xFF;
            if (nextHdr != 6) return null;
            int tcpOff = ipOff + 40;
            int srcPort = ((bytes[tcpOff] & 0xFF) << 8) | (bytes[tcpOff + 1] & 0xFF);
            int dstPort = ((bytes[tcpOff + 2] & 0xFF) << 8) | (bytes[tcpOff + 3] & 0xFF);
            if (srcPort != serverPort && dstPort != serverPort) return null;
            int doff = ((bytes[tcpOff + 12] >> 4) & 0xF) * 4;
            int payloadOff = tcpOff + doff;
            int payloadLen = Math.max(0, bytes.length - payloadOff);
            long seq = ((long)(bytes[tcpOff + 4] & 0xFF) << 24) |
                       ((long)(bytes[tcpOff + 5] & 0xFF) << 16) |
                       ((long)(bytes[tcpOff + 6] & 0xFF) << 8) |
                       ((long)(bytes[tcpOff + 7] & 0xFF));
            String dir = (dstPort == serverPort) ? "C->S" : "S->C";
            return new Segment(dir, ts, srcPort, dstPort, seq, bytes, payloadOff, payloadLen);
        }
        return null;
    }
}


