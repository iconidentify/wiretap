package com.wiretap.services.atomforge;

import java.util.Objects;

/**
 * Result of an AtomForge health check.
 */
public final class HealthCheckResult {
    private final boolean available;
    private final String version;
    private final String daemonStatus;
    private final String errorMessage;

    private HealthCheckResult(boolean available, String version, String daemonStatus, String errorMessage) {
        this.available = available;
        this.version = version;
        this.daemonStatus = daemonStatus;
        this.errorMessage = errorMessage;
    }

    public static HealthCheckResult success(String version, String daemonStatus) {
        return new HealthCheckResult(true, version, daemonStatus, null);
    }

    public static HealthCheckResult failure(String errorMessage) {
        return new HealthCheckResult(false, null, null, errorMessage);
    }

    public boolean isAvailable() {
        return available;
    }

    public String getVersion() {
        return version;
    }

    public String getDaemonStatus() {
        return daemonStatus;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof HealthCheckResult)) return false;
        HealthCheckResult that = (HealthCheckResult) o;
        return available == that.available &&
               Objects.equals(version, that.version) &&
               Objects.equals(daemonStatus, that.daemonStatus) &&
               Objects.equals(errorMessage, that.errorMessage);
    }

    @Override
    public int hashCode() {
        return Objects.hash(available, version, daemonStatus, errorMessage);
    }

    @Override
    public String toString() {
        if (available) {
            return "HealthCheckResult{available=true, version='" + version + "', daemonStatus='" + daemonStatus + "'}";
        } else {
            return "HealthCheckResult{available=false, error='" + errorMessage + "'}";
        }
    }
}
