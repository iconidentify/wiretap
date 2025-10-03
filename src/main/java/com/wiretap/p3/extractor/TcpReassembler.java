package com.wiretap.p3.extractor;

import java.util.TreeMap;
import java.util.function.Consumer;

public final class TcpReassembler {

    private long nextSeq = -1L;
    private final TreeMap<Long, byte[]> ooo = new TreeMap<>();
    private byte[] buffer = new byte[1 << 16];
    private int bufLen = 0;

    public void onSegment(long seq, byte[] bytes, int off, int len) {
        if (len <= 0) return;
        if (nextSeq < 0) {
            ensureCapacity(bufLen + len);
            System.arraycopy(bytes, off, buffer, bufLen, len);
            bufLen += len;
            nextSeq = seq + len;
            foldContiguous();
            return;
        }
        if (seq == nextSeq) {
            ensureCapacity(bufLen + len);
            System.arraycopy(bytes, off, buffer, bufLen, len);
            bufLen += len;
            nextSeq += len;
            foldContiguous();
        } else if (seq > nextSeq) {
            byte[] copy = new byte[len];
            System.arraycopy(bytes, off, copy, 0, len);
            ooo.put(seq, copy);
        } else {
            int skip = (int) (nextSeq - seq);
            if (skip < len) {
                int rem = len - skip;
                ensureCapacity(bufLen + rem);
                System.arraycopy(bytes, off + skip, buffer, bufLen, rem);
                bufLen += rem;
                nextSeq += rem;
                foldContiguous();
            }
        }
    }

    private void foldContiguous() {
        while (true) {
            byte[] seg = ooo.remove(nextSeq);
            if (seg == null) break;
            ensureCapacity(bufLen + seg.length);
            System.arraycopy(seg, 0, buffer, bufLen, seg.length);
            bufLen += seg.length;
            nextSeq += seg.length;
        }
    }

    public int drainTo(Consumer<byte[]> sink) {
        if (bufLen == 0) return 0;
        byte[] out = new byte[bufLen];
        System.arraycopy(buffer, 0, out, 0, bufLen);
        sink.accept(out);
        int n = bufLen;
        bufLen = 0;
        return n;
    }

    private void ensureCapacity(int need) {
        if (need <= buffer.length) return;
        int newCap = buffer.length;
        while (newCap < need) newCap <<= 1;
        byte[] nb = new byte[newCap];
        System.arraycopy(buffer, 0, nb, 0, bufLen);
        buffer = nb;
    }
}


