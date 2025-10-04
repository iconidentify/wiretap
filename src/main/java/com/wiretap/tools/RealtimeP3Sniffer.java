package com.wiretap.tools;

import com.wiretap.aol.extractor.EthernetDecoder;
import com.wiretap.aol.extractor.LinkDecoder;
import com.wiretap.core.FrameParser;
import com.wiretap.core.HexUtil;
import com.wiretap.extractor.FrameSummary;
import com.wiretap.web.LiveBus;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal TCP proxy that forwards P3 TCP traffic and emits JSONL summaries live to the LiveBus (SSE).
 * Note: This is a simple implementation, not optimized for high throughput.
 */
public final class RealtimeP3Sniffer {
    public static void main(String[] args) throws Exception {
        int listenPort = 5190;
        String destHost = "127.0.0.1";
        int destPort = 5190;
        for (int i = 0; i < args.length; i++) {
            String k = args[i];
            String v = (i + 1 < args.length) ? args[i + 1] : null;
            switch (k) {
                case "--listen-port" -> listenPort = Integer.parseInt(v);
                case "--dest-host" -> destHost = v;
                case "--dest-port" -> destPort = Integer.parseInt(v);
            }
        }
        System.out.println("Proxy listening on :" + listenPort + " -> " + destHost + ":" + destPort);
        try (ServerSocket server = new ServerSocket(listenPort)) {
            while (true) {
                Socket client = server.accept();
                Socket serverSock = new Socket();
                serverSock.connect(new InetSocketAddress(destHost, destPort));
                new Thread(new Pipe(client, serverSock, true)).start();
                new Thread(new Pipe(serverSock, client, false)).start();
            }
        }
    }

    private static final class Pipe implements Runnable, Closeable {
        private final Socket in;
        private final Socket out;
        private final boolean c2s;
        private final LinkDecoder link = new EthernetDecoder();

        private Pipe(Socket in, Socket out, boolean c2s) { this.in = in; this.out = out; this.c2s = c2s; }

        @Override
        public void run() {
            try {
                var inStr = in.getInputStream();
                var outStr = out.getOutputStream();
                byte[] buf = new byte[8192];
                while (true) {
                    int n = inStr.read(buf);
                    if (n < 0) break;
                    // forward
                    outStr.write(buf, 0, n);
                    outStr.flush();
                    // naive scan for P3 frames in this chunk
                    List<FrameSummary> frames = new ArrayList<>();
                    scanP3(buf, 0, n, c2s ? "C->S" : "S->C", frames);
                    for (FrameSummary fs : frames) {
                        LiveBus.publish(fs.toJson(false));
                    }
                }
            } catch (IOException ignored) {
            } finally {
                try { close(); } catch (IOException ignored) {}
            }
        }

        @Override
        public void close() throws IOException {
            try { in.close(); } catch (IOException ignored) {}
            try { out.close(); } catch (IOException ignored) {}
        }
    }

    // Lightweight scanner mirroring P3Extractor.scanFrames/summarize behavior for streaming chunks
    private static void scanP3(byte[] a, int start, int end, String dir, List<FrameSummary> out) {
        int i = start;
        while (i + 6 <= end) {
            if ((a[i] & 0xFF) != 0x5A) { i++; continue; }
            if (i + 10 > end) break;
            int len = ((a[i+3] & 0xFF) << 8) | (a[i+4] & 0xFF);
            int total = 6 + len;
            if (i + total > end) break;
            out.add(summarize(dir, a, i, total));
            i += total;
        }
    }

    private static FrameSummary summarize(String dir, byte[] f, int off, int length) {
        // Use centralized FrameParser.parseLite() for real-time parsing
        return FrameParser.parseLite(dir, f, off, length);
    }

    private static String bytesToHexLower(byte[] a, int off, int len) {
        // Delegate to centralized HexUtil
        return HexUtil.bytesToHexLower(a, off, len);
    }
}


