package com.wiretap.web;

import com.wiretap.extractor.FrameSummary;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

/**
 * Lightweight TCP proxy for AOL traffic that mirrors frames to LiveBus as JSONL.
 */
final class TcpProxyService implements Closeable {
    private final int listenPort;
    private final String destHost;
    private final int destPort;
    private Thread acceptThread;
    private volatile boolean running;
    private final List<Pipe> pipes = new ArrayList<>();
    private ServerSocket serverSocket;

    TcpProxyService(int listenPort, String destHost, int destPort) {
        this.listenPort = listenPort;
        this.destHost = destHost; this.destPort = destPort;
    }

    public int getListenPort() {
        return listenPort;
    }

    void start() {
        if (running) return;
        running = true;
        acceptThread = new Thread(() -> {
            try {
                serverSocket = new ServerSocket(listenPort);  // Assign to field
                System.out.println("[AOL-PROXY] listening on :" + listenPort + " -> " + destHost + ":" + destPort);
                while (running && !serverSocket.isClosed()) {  // Check closed
                    Socket client = serverSocket.accept();
                    System.out.println("[AOL-PROXY] client connected: " + client.getRemoteSocketAddress());
                    Socket serverSock = new Socket();
                    serverSock.connect(new InetSocketAddress(destHost, destPort));
                    Pipe c2s = new Pipe(client, serverSock, true);
                    Pipe s2c = new Pipe(serverSock, client, false);
                    synchronized (pipes) { pipes.add(c2s); pipes.add(s2c); }
                    new Thread(c2s).start();
                    new Thread(s2c).start();
                }
            } catch (IOException ignored) {}
        }, "aol-proxy-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    boolean isRunning() { return running; }

    @Override
    public void close() {
        running = false;
        if (serverSocket != null && !serverSocket.isClosed()) {
            try { serverSocket.close(); } catch (IOException ignored) {}
        }
        if (acceptThread != null) {
            acceptThread.interrupt();
            try { acceptThread.join(1000); } catch (InterruptedException ignored) {}
        }
        synchronized (pipes) {
            for (Pipe p : pipes) {
                try {
                    p.in.shutdownInput();
                    p.out.shutdownOutput();
                    p.close();
                } catch (IOException ignored) {}
            }
            pipes.clear();
        }
    }

    private static final class Pipe implements Runnable, Closeable {
        private final Socket in;
        private final Socket out;
        private final boolean c2s;
        private byte[] residual = new byte[0];
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
                    outStr.write(buf, 0, n); outStr.flush();
                    processChunk(buf, 0, n, c2s ? "C->S" : "S->C");
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
        private void processChunk(byte[] chunk, int off, int len, String dir) {
            System.out.println("[AOL-PROXY-DBG] " + dir + " chunk: " + len + " bytes");
            // merge residual + chunk
            byte[] a;
            int start;
            int end;
            if (residual.length > 0) {
                a = new byte[residual.length + len];
                System.arraycopy(residual, 0, a, 0, residual.length);
                System.arraycopy(chunk, off, a, residual.length, len);
                start = 0;
                end = a.length;
                residual = new byte[0];
            } else {
                a = chunk;
                start = off;
                end = off + len;
            }
            int consumed = scanAol(a, start, end, dir);
            int leftover = end - (start + consumed);
            if (leftover > 0) {
                residual = new byte[leftover];
                System.arraycopy(a, start + consumed, residual, 0, leftover);
            }
            if (consumed == 0 && len > 0) {
                System.out.println("[AOL-PROXY-DBG] No frames in chunk; hex sample: " + bytesToHexLower(chunk, off, Math.min(32, len)));
            }
        }
    }

    private static int scanAol(byte[] a, int start, int end, String dir) {
        int i = start;
        int frames = 0;
        while (i + 6 <= end) {
            if ((a[i] & 0xFF) != 0x5A) { i++; continue; }
            if (i + 10 > end) break;
            int len = ((a[i+3] & 0xFF) << 8) | (a[i+4] & 0xFF);
            int total = 6 + len;
            if (i + total > end) break;
            FrameSummary fs = summarize(dir, a, i, total);
            LiveBus.publish(fs.toJson(false));
            frames++;
            i += total;
        }
        if (frames > 0) System.out.println("[AOL-PROXY] " + dir + " frames: " + frames);
        return i - start;
    }

    private static FrameSummary summarize(String dir, byte[] f, int off, int length) {
        FrameSummary s = new FrameSummary();
        s.dir = dir;
        s.ts  = String.valueOf(System.currentTimeMillis()/1000.0);
        s.len = length >= 6 ? (((f[off+3] & 0xFF) << 8) | (f[off+4] & 0xFF)) : 0;
        s.type = length > 7 ? String.format("0x%02X", f[off+7] & 0xFF) : "n/a";
        s.tx = length > 5 ? String.format("0x%02X", f[off+5] & 0xFF) : "n/a";
        s.rx = length > 6 ? String.format("0x%02X", f[off+6] & 0xFF) : "n/a";
        if (length >= 10 && (f[off] & 0xFF) == 0x5A) {
            char c1 = (char)(f[off+8] & 0xFF), c2 = (char)(f[off+9] & 0xFF);
            if (c1 >= 32 && c1 < 127 && c2 >= 32 && c2 < 127) s.token = ""+c1+c2;
            else s.token = String.format("0x%02x%02x", f[off+8] & 0xFF, f[off+9] & 0xFF);
            // Extract streamId (2 bytes after token at offset 10-11)
            if (length >= 12) {
                s.streamId = String.format("0x%02x%02x", f[off+10] & 0xFF, f[off+11] & 0xFF);
            }
        } else if (length == 9 && (f[off] & 0xFF) == 0x5A) { s.token = "9B"; }
        s.fullHex = bytesToHexLower(f, off, length);
        return s;
    }

    private static String bytesToHexLower(byte[] a, int off, int len) {
        final char[] HEX = "0123456789abcdef".toCharArray();
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++) {
            int b = a[off + i] & 0xFF;
            sb.append(HEX[(b >>> 4) & 0xF]).append(HEX[b & 0xF]);
        }
        return sb.toString();
    }
}


