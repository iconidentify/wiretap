package com.wiretap.extractor;

import com.wiretap.core.FrameParser;
import com.wiretap.core.HexUtil;
import com.wiretap.extractor.io.FullFrameStore;
import com.wiretap.extractor.io.SummaryWriter;
import com.wiretap.p3.extractor.EthernetDecoder;
import com.wiretap.p3.extractor.LinkDecoder;
import com.wiretap.tools.PcapReader;
import com.wiretap.p3.extractor.TcpReassembler;

import java.time.Instant;
import java.util.*;

/**
 * Core PCAP → P3 frame extractor.
 */
public final class P3Extractor {

    private static final int P3_MAGIC = 0x5A;

    private static final class DirKey {
        final String src, dst;
        final int sport, dport;
        final boolean c2s;
        DirKey(String src, int sport, String dst, int dport, boolean c2s) {
            this.src = src; this.sport = sport; this.dst = dst; this.dport = dport; this.c2s = c2s;
        }
        @Override public int hashCode() { return Objects.hash(src,sport,dst,dport,c2s); }
        @Override public boolean equals(Object o) {
            if (!(o instanceof DirKey k)) return false;
            return c2s==k.c2s && sport==k.sport && dport==k.dport && Objects.equals(src,k.src) && Objects.equals(dst,k.dst);
        }
    }

    private static final class StreamBuf {
        private byte[] residual = new byte[1024];
        private int length = 0;

        int size() { return length; }
        void clear() { length = 0; }
        private void ensureCapacity(int need) {
            if (need <= residual.length) return;
            int cap = residual.length;
            while (cap < need) cap <<= 1;
            byte[] nb = new byte[cap];
            System.arraycopy(residual, 0, nb, 0, length);
            residual = nb;
        }
        void setResidual(byte[] src, int off, int len) {
            ensureCapacity(len);
            System.arraycopy(src, off, residual, 0, len);
            length = len;
        }
        byte[] array() { return residual; }
    }

    public void extract(String pcapPath,
                        int serverPort,
                        boolean pretty,
                        boolean storeFull,
                        SummaryWriter summaryWriter,
                        FullFrameStore fullFrameStoreOrNull) throws Exception {

        java.util.logging.Logger.getLogger("pcap-extractor").info("[P3-PCAP] reading: " + pcapPath);

        List<FrameSummary> frames = new ArrayList<>();

        boolean sawTcpPort = false;
        boolean sawIpv4 = false;
        boolean sawIpv6 = false;
        byte[] firstPacketBytes = null;
        int network = -1;

        try (PcapReader reader = new PcapReader(pcapPath)) {
            network = reader.getLinkType();
            LinkDecoder decoder = new EthernetDecoder();
            Map<DirKey, TcpReassembler> reassemblers = new LinkedHashMap<>();
            Map<DirKey, StreamBuf> streams = new LinkedHashMap<>();

            long packetCount = 0;
            for (PcapReader.Record rec; (rec = reader.next()) != null; ) {
                packetCount++;
                if (firstPacketBytes == null) {
                    firstPacketBytes = java.util.Arrays.copyOf(rec.bytes, Math.min(rec.bytes.length, 32));
                }
                LinkDecoder.Segment seg = decoder.decode(rec.linkType, rec.timestamp, rec.bytes, serverPort);
                if (seg == null) continue;
                if (seg.srcPort == serverPort || seg.dstPort == serverPort) sawTcpPort = true;
                int ipVer = (rec.bytes.length > 0) ? ((rec.bytes[0] >> 4) & 0xF) : 0;
                if (ipVer == 4) sawIpv4 = true; if (ipVer == 6) sawIpv6 = true;

                if (seg.len > 0) {
                    DirKey key = new DirKey("p" + seg.srcPort, seg.srcPort, "p" + seg.dstPort, seg.dstPort, "C->S".equals(seg.dir));
                    TcpReassembler r = reassemblers.computeIfAbsent(key, k -> new TcpReassembler());
                    r.onSegment(seg.seq, seg.bytes, seg.off, seg.len);
                    java.util.function.Consumer<byte[]> sink = bytes -> {
                        StreamBuf sb = streams.computeIfAbsent(key, k -> new StreamBuf());
                        processChunk(bytes, 0, bytes.length, seg.dir, seg.ts, sb, frames);
                    };
                    r.drainTo(sink);
                }
            }
            java.util.logging.Logger.getLogger("pcap-extractor").info("[P3-PCAP] processed " + packetCount + " packets");
        }

        java.util.logging.Logger.getLogger("pcap-extractor").info("[P3-PCAP] frames parsed: " + frames.size());

        if (frames.size() == 0) {
            java.util.logging.Logger.getLogger("pcap-extractor").warning("[P3-PCAP] DIAGNOSTIC: No frames parsed!");
            java.util.logging.Logger.getLogger("pcap-extractor").info("  - linktype: " + network);
            java.util.logging.Logger.getLogger("pcap-extractor").info("  - saw IPv4: " + sawIpv4);
            java.util.logging.Logger.getLogger("pcap-extractor").info("  - saw IPv6: " + sawIpv6);
            java.util.logging.Logger.getLogger("pcap-extractor").info("  - saw TCP port " + serverPort + ": " + sawTcpPort);
            if (firstPacketBytes != null) {
                java.util.logging.Logger.getLogger("pcap-extractor").info("  - first packet bytes: " + HexUtil.bytesToHexLower(firstPacketBytes, 0, Math.min(firstPacketBytes.length, 32)));
            }
            if (!sawIpv4 && !sawIpv6) {
                java.util.logging.Logger.getLogger("pcap-extractor").info("  - HINT: No IPv4/IPv6 packets found - check linktype and packet format");
            }
            if (!sawTcpPort) {
                java.util.logging.Logger.getLogger("pcap-extractor").info("  - HINT: No TCP port " + serverPort + " traffic found - check if this is P3 traffic");
            }
        }

        Map<String,Integer> repeatCounts = new HashMap<>();

        for (FrameSummary fs : frames) {
            if (storeFull && fs.fullHex != null && fullFrameStoreOrNull != null) {
                String sha1 = sha1Hex(fs.fullHex);
                if (!fullFrameStoreOrNull.contains(sha1)) {
                    fullFrameStoreOrNull.put(sha1, fs.fullHex);
                } else {
                    repeatCounts.merge(sha1, 1, Integer::sum);
                }
                fs.ref = sha1;
                if (fs.fullHex.length() > 512) fs.fullHex = null; // keep tiny ones inline
            }
            summaryWriter.write(fs);
        }

        if (storeFull && !repeatCounts.isEmpty()) {
            java.util.logging.Logger.getLogger("pcap-extractor").info("[P3-PCAP] dedup stats: " + repeatCounts.size() + " repeated frames");
        }
    }

    private static void processChunk(byte[] chunk, int off, int len, String dir, Instant ts, StreamBuf sb, List<FrameSummary> out) {
        byte[] a;
        int start;
        int end;
        if (sb.size() > 0) {
            a = new byte[sb.size() + len];
            System.arraycopy(sb.array(), 0, a, 0, sb.size());
            System.arraycopy(chunk, off, a, sb.size(), len);
            start = 0;
            end = a.length;
            sb.clear();
        } else {
            a = chunk;
            start = off;
            end = off + len;
        }

        int consumed = scanFrames(a, start, end, dir, ts, out);
        int leftover = end - (start + consumed);
        if (leftover > 0) {
            int loff = start + consumed;
            sb.setResidual(a, loff, leftover);
        }
    }

    private static int scanFrames(byte[] a, int start, int end, String dir, Instant ts, List<FrameSummary> out) {
        int i = start;
        while (i + 6 <= end) {
            if ((a[i] & 0xFF) != P3_MAGIC) { i++; continue; }

            if (i + 9 <= end && (a[i+7] & 0xFF) != 0x20 && (a[i+7] & 0xF0) == 0xA0) {
                int len = ((a[i+3] & 0xFF) << 8) | (a[i+4] & 0xFF);
                if (len == 3 && i + 9 <= end) {
                    out.add(summarize(dir, ts, a, i, 9));
                    i += 9;
                    continue;
                }
            }

            if (i + 10 > end) break;
            int len = ((a[i+3] & 0xFF) << 8) | (a[i+4] & 0xFF);
            int total = 6 + len;
            if (i + total > end) break;
            out.add(summarize(dir, ts, a, i, total));
            i += total;
        }
        return i - start;
    }

    private static FrameSummary summarize(String dir, Instant ts, byte[] f, int off, int length) {
        // Use centralized FrameParser instead of duplicated logic
        return FrameParser.parse(dir, ts, f, off, length);
    }

    private static String sha1Hex(String hex) throws Exception {
        // Delegate to centralized HexUtil
        return HexUtil.sha1Hex(hex);
    }
}


