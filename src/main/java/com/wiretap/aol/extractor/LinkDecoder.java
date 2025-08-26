package com.wiretap.aol.extractor;

import java.time.Instant;

public interface LinkDecoder {
    final class Segment {
        public final String dir;
        public final Instant ts;
        public final int srcPort;
        public final int dstPort;
        public final long seq;
        public final byte[] bytes;
        public final int off;
        public final int len;

        public Segment(String dir, Instant ts, int srcPort, int dstPort, long seq, byte[] bytes, int off, int len) {
            this.dir = dir;
            this.ts = ts;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.seq = seq;
            this.bytes = bytes;
            this.off = off;
            this.len = len;
        }
    }

    Segment decode(int linkType, Instant ts, byte[] packetBytes, int serverPort);
}


