package com.wiretap.session;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Metadata about a capture session, stored alongside the session JSONL file.
 */
public final class SessionInfo {
    private static final DateTimeFormatter FILENAME_FORMAT =
        DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss").withZone(ZoneId.systemDefault());

    private final String id;
    private final Instant startTime;
    private volatile Instant endTime;
    private volatile long frameCount;
    private volatile long fileSizeBytes;
    private volatile boolean active;

    public SessionInfo(String id) {
        this.id = id;
        this.startTime = Instant.now();
        this.frameCount = 0;
        this.fileSizeBytes = 0;
        this.active = true;
    }

    /**
     * Creates a SessionInfo from metadata JSON (for loading existing sessions).
     */
    public SessionInfo(String id, Instant startTime, Instant endTime,
                       long frameCount, long fileSizeBytes, boolean active) {
        this.id = id;
        this.startTime = startTime;
        this.endTime = endTime;
        this.frameCount = frameCount;
        this.fileSizeBytes = fileSizeBytes;
        this.active = active;
    }

    public String getId() {
        return id;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }

    public long getFrameCount() {
        return frameCount;
    }

    public long getFileSizeBytes() {
        return fileSizeBytes;
    }

    public boolean isActive() {
        return active;
    }

    public void incrementFrameCount() {
        frameCount++;
    }

    public void setFrameCount(long count) {
        this.frameCount = count;
    }

    public void setFileSizeBytes(long bytes) {
        this.fileSizeBytes = bytes;
    }

    public void markEnded() {
        this.active = false;
        this.endTime = Instant.now();
    }

    /**
     * Generates a unique session ID based on timestamp and random component.
     */
    private static java.util.concurrent.atomic.AtomicLong idCounter = new java.util.concurrent.atomic.AtomicLong(System.nanoTime());

    public static String generateId() {
        String timestamp = FILENAME_FORMAT.format(Instant.now());
        // Use atomic counter + nanoTime for guaranteed uniqueness
        long unique = idCounter.incrementAndGet() ^ System.nanoTime();
        String random = Long.toHexString(unique & 0xFFFFFFL);
        // Pad to ensure consistent length
        while (random.length() < 6) random = "0" + random;
        return "session-" + timestamp + "-" + random.substring(0, 6);
    }

    /**
     * Formats file size for human-readable display.
     */
    public String getFormattedSize() {
        if (fileSizeBytes < 1024) {
            return fileSizeBytes + " B";
        } else if (fileSizeBytes < 1024 * 1024) {
            return String.format("%.1f KB", fileSizeBytes / 1024.0);
        } else if (fileSizeBytes < 1024 * 1024 * 1024) {
            return String.format("%.1f MB", fileSizeBytes / (1024.0 * 1024));
        } else {
            return String.format("%.2f GB", fileSizeBytes / (1024.0 * 1024 * 1024));
        }
    }

    /**
     * Returns session duration in seconds.
     */
    public long getDurationSeconds() {
        Instant end = endTime != null ? endTime : Instant.now();
        return end.getEpochSecond() - startTime.getEpochSecond();
    }

    /**
     * Formats duration as HH:MM:SS.
     */
    public String getFormattedDuration() {
        long seconds = getDurationSeconds();
        long hours = seconds / 3600;
        long minutes = (seconds % 3600) / 60;
        long secs = seconds % 60;
        return String.format("%d:%02d:%02d", hours, minutes, secs);
    }

    /**
     * Serializes to JSON for the metadata file.
     */
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"id\":\"").append(escapeJson(id)).append("\"");
        sb.append(",\"startTime\":\"").append(startTime.toString()).append("\"");
        if (endTime != null) {
            sb.append(",\"endTime\":\"").append(endTime.toString()).append("\"");
        }
        sb.append(",\"frameCount\":").append(frameCount);
        sb.append(",\"fileSizeBytes\":").append(fileSizeBytes);
        sb.append(",\"active\":").append(active);
        sb.append(",\"formattedSize\":\"").append(escapeJson(getFormattedSize())).append("\"");
        sb.append(",\"formattedDuration\":\"").append(getFormattedDuration()).append("\"");
        sb.append("}");
        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * Parses SessionInfo from JSON metadata.
     */
    public static SessionInfo fromJson(String json) {
        // Simple manual JSON parsing
        String id = extractString(json, "id");
        String startTimeStr = extractString(json, "startTime");
        String endTimeStr = extractString(json, "endTime");
        long frameCount = extractLong(json, "frameCount");
        long fileSizeBytes = extractLong(json, "fileSizeBytes");
        boolean active = extractBoolean(json, "active");

        Instant startTime = startTimeStr != null ? Instant.parse(startTimeStr) : Instant.now();
        Instant endTime = endTimeStr != null ? Instant.parse(endTimeStr) : null;

        return new SessionInfo(id, startTime, endTime, frameCount, fileSizeBytes, active);
    }

    private static String extractString(String json, String key) {
        String pattern = "\"" + key + "\":\"";
        int start = json.indexOf(pattern);
        if (start < 0) return null;
        start += pattern.length();
        int end = json.indexOf("\"", start);
        if (end < 0) return null;
        return json.substring(start, end);
    }

    private static long extractLong(String json, String key) {
        String pattern = "\"" + key + "\":";
        int start = json.indexOf(pattern);
        if (start < 0) return 0;
        start += pattern.length();
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) {
            end++;
        }
        try {
            return Long.parseLong(json.substring(start, end));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static boolean extractBoolean(String json, String key) {
        String pattern = "\"" + key + "\":";
        int start = json.indexOf(pattern);
        if (start < 0) return false;
        start += pattern.length();
        return json.substring(start).trim().startsWith("true");
    }
}
