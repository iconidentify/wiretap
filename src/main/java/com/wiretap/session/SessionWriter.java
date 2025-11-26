package com.wiretap.session;

import com.wiretap.core.WireTapLog;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Batched, append-only JSONL writer for session frames.
 * <p>
 * Frames are buffered in memory and flushed to disk every 100ms.
 * This reduces I/O overhead while ensuring data durability.
 * <p>
 * Thread-safe for concurrent append operations.
 */
public final class SessionWriter implements Closeable {
    private static final int FLUSH_INTERVAL_MS = 100;
    private static final int INITIAL_BUFFER_CAPACITY = 100;

    private final Path sessionFile;
    private final SessionInfo sessionInfo;
    private final List<String> writeBuffer;
    private final ScheduledExecutorService flusher;
    private final AtomicLong frameCount;
    private final Object bufferLock = new Object();

    private volatile boolean closed = false;
    private volatile ScheduledFuture<?> flushTask;
    private volatile long lastFlushTime;

    /**
     * Creates a new session writer.
     *
     * @param sessionFile Path to the JSONL session file
     * @param sessionInfo Session metadata object to update
     */
    public SessionWriter(Path sessionFile, SessionInfo sessionInfo) throws IOException {
        this.sessionFile = sessionFile;
        this.sessionInfo = sessionInfo;
        this.writeBuffer = new ArrayList<>(INITIAL_BUFFER_CAPACITY);
        this.frameCount = new AtomicLong(0);
        this.lastFlushTime = System.currentTimeMillis();

        // Ensure parent directory exists
        Path parent = sessionFile.getParent();
        if (parent != null && !Files.exists(parent)) {
            Files.createDirectories(parent);
        }

        // Create or truncate the session file
        if (!Files.exists(sessionFile)) {
            Files.createFile(sessionFile);
        }

        // Start the background flusher
        this.flusher = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "session-writer-flush");
            t.setDaemon(true);
            return t;
        });

        this.flushTask = flusher.scheduleAtFixedRate(
            this::periodicFlush,
            FLUSH_INTERVAL_MS,
            FLUSH_INTERVAL_MS,
            TimeUnit.MILLISECONDS
        );

        WireTapLog.info("SessionWriter started for: " + sessionFile.getFileName());
    }

    /**
     * Appends a JSONL line to the buffer.
     * The line will be written to disk on the next flush cycle.
     *
     * @param jsonlLine A single JSONL line (frame data)
     */
    public void append(String jsonlLine) {
        if (closed) {
            WireTapLog.warn("Attempted to write to closed SessionWriter");
            return;
        }

        synchronized (bufferLock) {
            writeBuffer.add(jsonlLine);
        }
        frameCount.incrementAndGet();
        sessionInfo.incrementFrameCount();
    }

    /**
     * Returns the current frame count.
     */
    public long getFrameCount() {
        return frameCount.get();
    }

    /**
     * Returns the session file path.
     */
    public Path getSessionFile() {
        return sessionFile;
    }

    /**
     * Returns the session info.
     */
    public SessionInfo getSessionInfo() {
        return sessionInfo;
    }

    /**
     * Forces an immediate flush of buffered data to disk.
     */
    public void flush() {
        doFlush(true);
    }

    /**
     * Periodic flush called by the scheduler.
     */
    private void periodicFlush() {
        if (!closed) {
            doFlush(false);
        }
    }

    /**
     * Internal flush implementation.
     */
    private void doFlush(boolean force) {
        List<String> toWrite;

        synchronized (bufferLock) {
            if (writeBuffer.isEmpty()) {
                return;
            }
            toWrite = new ArrayList<>(writeBuffer);
            writeBuffer.clear();
        }

        if (toWrite.isEmpty()) {
            return;
        }

        try {
            // Build the data to write
            StringBuilder sb = new StringBuilder();
            for (String line : toWrite) {
                sb.append(line).append("\n");
            }
            byte[] data = sb.toString().getBytes(StandardCharsets.UTF_8);

            // Write with exclusive lock
            try (FileChannel channel = FileChannel.open(sessionFile,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND,
                    StandardOpenOption.CREATE)) {

                channel.write(ByteBuffer.wrap(data));
                channel.force(true); // fsync for durability
            }

            // Update metadata
            try {
                sessionInfo.setFileSizeBytes(Files.size(sessionFile));
            } catch (IOException ignored) {
                // Best effort size update
            }

            lastFlushTime = System.currentTimeMillis();

            if (force) {
                WireTapLog.debug("SessionWriter forced flush: " + toWrite.size() + " frames");
            }
        } catch (IOException e) {
            WireTapLog.error("Failed to flush session data", e);
            // Re-add to buffer for retry
            synchronized (bufferLock) {
                writeBuffer.addAll(0, toWrite);
            }
        }
    }

    /**
     * Returns time since last flush in milliseconds.
     */
    public long getTimeSinceLastFlush() {
        return System.currentTimeMillis() - lastFlushTime;
    }

    /**
     * Returns the number of frames waiting in the buffer.
     */
    public int getBufferedFrameCount() {
        synchronized (bufferLock) {
            return writeBuffer.size();
        }
    }

    /**
     * Closes the writer, flushing any remaining data.
     */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;

        // Cancel scheduled task
        if (flushTask != null) {
            flushTask.cancel(false);
        }

        // Shutdown executor
        flusher.shutdown();
        try {
            if (!flusher.awaitTermination(1, TimeUnit.SECONDS)) {
                flusher.shutdownNow();
            }
        } catch (InterruptedException e) {
            flusher.shutdownNow();
            Thread.currentThread().interrupt();
        }

        // Final flush
        doFlush(true);

        // Mark session as ended
        sessionInfo.markEnded();

        WireTapLog.info("SessionWriter closed: " + sessionFile.getFileName() +
                        ", total frames: " + frameCount.get());
    }
}
