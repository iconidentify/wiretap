package com.wiretap.web;

import java.time.Instant;

/**
 * Metadata for a TCP proxy connection, used for session-based filtering.
 */
public final class ConnectionInfo {
    public final String connectionId;
    public final String sourceIp;
    public final int sourcePort;
    public final String startTime;
    public volatile int frameCount;
    public volatile long lastActivityTime;
    public volatile boolean active;

    public ConnectionInfo(String connectionId, String sourceIp, int sourcePort) {
        this.connectionId = connectionId;
        this.sourceIp = sourceIp;
        this.sourcePort = sourcePort;
        this.startTime = Instant.now().toString();
        this.frameCount = 0;
        this.lastActivityTime = System.currentTimeMillis();
        this.active = true;
    }

    /**
     * Mark this connection as having processed a frame
     */
    public void incrementFrameCount() {
        frameCount++;
        lastActivityTime = System.currentTimeMillis();
    }

    /**
     * Mark this connection as closed
     */
    public void markClosed() {
        active = false;
    }

    /**
     * Get connection duration in seconds
     */
    public long getDurationSeconds() {
        return (System.currentTimeMillis() - Instant.parse(startTime).toEpochMilli()) / 1000;
    }

    /**
     * Convert to JSON for API responses
     */
    public String toJson() {
        return String.format(
            "{\"connectionId\":\"%s\",\"sourceIp\":\"%s\",\"sourcePort\":%d," +
            "\"startTime\":\"%s\",\"frameCount\":%d,\"active\":%s,\"durationSeconds\":%d}",
            connectionId, sourceIp, sourcePort, startTime, frameCount, active, getDurationSeconds()
        );
    }

    @Override
    public String toString() {
        return String.format("Connection{id=%s, source=%s:%d, frames=%d, active=%s}",
            connectionId, sourceIp, sourcePort, frameCount, active);
    }
}