package com.wiretap.tools;

import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;

public final class PcapReader implements Closeable {

    public static final class Record {
        public final int linkType;
        public final Instant timestamp;
        public final byte[] bytes;

        Record(int linkType, Instant ts, byte[] bytes) {
            this.linkType = linkType;
            this.timestamp = ts;
            this.bytes = bytes;
        }
    }

    private static final int PCAP_MAGIC = 0xA1B2C3D4;
    private static final int PCAP_MAGIC_SWAPPED = 0xD4C3B2A1;
    private static final int PCAPNG_MAGIC = 0x0A0D0D0A;

    private final FileInputStream fis;
    private final ByteOrder order;
    private final int linkType;
    private final ByteBuffer pktHdr;

    public PcapReader(String path) throws IOException {
        this.fis = new FileInputStream(path);
        ByteBuffer header = ByteBuffer.allocate(24);
        int rd = fis.read(header.array());
        if (rd != 24) throw new IOException("Invalid PCAP: too short");

        int magic = header.getInt(0);
        if (magic == PCAPNG_MAGIC) {
            throw new IOException("pcapng is not supported");
        }
        boolean swapped = (magic == PCAP_MAGIC_SWAPPED);
        if (magic != PCAP_MAGIC && magic != PCAP_MAGIC_SWAPPED) {
            throw new IOException("Invalid PCAP magic: 0x" + Integer.toHexString(magic));
        }
        this.order = swapped ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;
        header.order(order);

        int major = header.getInt(4) & 0xFFFF;
        int minor = header.getInt(6) & 0xFFFF;
        if (!(major == 2 && minor == 4)) {
            // non-fatal
        }

        int snapLen = header.getInt(16);
        this.linkType = header.getInt(20);

        this.pktHdr = ByteBuffer.allocate(16);
        this.pktHdr.order(order);
    }

    public int getLinkType() { return linkType; }

    public Record next() throws IOException {
        int headerRead = fis.read(pktHdr.array());
        if (headerRead < 0) return null;
        if (headerRead != 16) throw new IOException("Unexpected EOF reading packet header");

        int tsSec = pktHdr.getInt(0);
        int tsUsec = pktHdr.getInt(4);
        int inclLen = pktHdr.getInt(8);
        pktHdr.getInt(12);

        if (inclLen <= 0 || inclLen > 65536) {
            return next();
        }
        byte[] bytes = new byte[inclLen];
        int rd = fis.read(bytes);
        if (rd != inclLen) throw new IOException("Unexpected EOF reading packet bytes");
        Instant ts = Instant.ofEpochSecond(tsSec, tsUsec * 1000L);
        return new Record(this.linkType, ts, bytes);
    }

    @Override
    public void close() throws IOException {
        fis.close();
    }
}


