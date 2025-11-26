package com.wiretap.web;

import com.wiretap.core.WireTapLog;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe registry for tracking active and recent TCP proxy connections.
 * Enables session-based filtering in the live capture interface.
 */
public final class ConnectionRegistry {
    private final Map<String, ConnectionInfo> connections = new ConcurrentHashMap<>();
    private volatile boolean enabled = true;

    /**
     * Register a new connection
     */
    public ConnectionInfo registerConnection(String connectionId, String sourceIp, int sourcePort) {
        if (!enabled) return null;

        ConnectionInfo info = new ConnectionInfo(connectionId, sourceIp, sourcePort);
        connections.put(connectionId, info);
        WireTapLog.debug("Registered connection: " + info);

        // Publish connection opened event
        LiveBus.publish(String.format(
            "{\"event\":\"connection_opened\",\"connectionId\":\"%s\",\"sourceIp\":\"%s\",\"sourcePort\":%d}",
            connectionId, sourceIp, sourcePort
        ));

        return info;
    }

    /**
     * Mark a connection as closed and publish event
     */
    public void closeConnection(String connectionId) {
        if (!enabled) return;

        ConnectionInfo info = connections.get(connectionId);
        if (info != null) {
            info.markClosed();
            WireTapLog.debug("Closed connection: " + info);

            // Publish connection closed event
            LiveBus.publish(String.format(
                "{\"event\":\"connection_closed\",\"connectionId\":\"%s\",\"frameCount\":%d}",
                connectionId, info.frameCount
            ));
        }
    }

    /**
     * Increment frame count for a connection
     */
    public void recordFrame(String connectionId) {
        if (!enabled) return;

        ConnectionInfo info = connections.get(connectionId);
        if (info != null) {
            info.incrementFrameCount();
        }
    }

    /**
     * Get all connections (active and recently closed)
     */
    public List<ConnectionInfo> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    /**
     * Get only active connections
     */
    public List<ConnectionInfo> getActiveConnections() {
        return connections.values().stream()
            .filter(conn -> conn.active)
            .toList();
    }

    /**
     * Get connection by ID
     */
    public ConnectionInfo getConnection(String connectionId) {
        return connections.get(connectionId);
    }

    /**
     * Check if a connection exists and is active
     */
    public boolean isConnectionActive(String connectionId) {
        ConnectionInfo info = connections.get(connectionId);
        return info != null && info.active;
    }

    /**
     * Get total frame count across all connections
     */
    public int getTotalFrameCount() {
        return connections.values().stream()
            .mapToInt(conn -> conn.frameCount)
            .sum();
    }

    /**
     * Clear all connections (used when proxy stops)
     */
    public void reset() {
        if (!enabled) return;

        WireTapLog.debug("Clearing connection registry (" + connections.size() + " connections)");
        connections.clear();

        // Publish registry reset event
        LiveBus.publish("{\"event\":\"connections_reset\"}");
    }

    /**
     * Generate JSON summary of all connections for API responses
     */
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"connections\":[");

        List<ConnectionInfo> conns = getAllConnections();
        for (int i = 0; i < conns.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(conns.get(i).toJson());
        }

        sb.append("],\"totalConnections\":").append(conns.size());
        sb.append(",\"activeConnections\":").append(getActiveConnections().size());
        sb.append(",\"totalFrames\":").append(getTotalFrameCount());
        sb.append("}");

        return sb.toString();
    }

    /**
     * Disable connection tracking (for testing or performance)
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        if (!enabled) {
            connections.clear();
        }
    }

    public boolean isEnabled() {
        return enabled;
    }
}