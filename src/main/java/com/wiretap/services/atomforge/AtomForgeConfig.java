package com.wiretap.services.atomforge;

import java.util.Objects;

/**
 * Immutable configuration for AtomForge integration.
 */
public final class AtomForgeConfig {
    private final String url;
    private final boolean enabled;
    private final int timeoutSeconds;

    private AtomForgeConfig(Builder builder) {
        this.url = builder.url;
        this.enabled = builder.enabled;
        this.timeoutSeconds = builder.timeoutSeconds;
    }

    public String getUrl() {
        return url;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int getTimeoutSeconds() {
        return timeoutSeconds;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(AtomForgeConfig config) {
        return new Builder()
            .url(config.url)
            .enabled(config.enabled)
            .timeoutSeconds(config.timeoutSeconds);
    }

    public static final class Builder {
        private String url = "http://localhost:8081";
        private boolean enabled = false;
        private int timeoutSeconds = 30;

        private Builder() {}

        public Builder url(String url) {
            this.url = url;
            return this;
        }

        public Builder enabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        public Builder timeoutSeconds(int timeoutSeconds) {
            this.timeoutSeconds = timeoutSeconds;
            return this;
        }

        public AtomForgeConfig build() {
            Objects.requireNonNull(url, "url cannot be null");
            if (timeoutSeconds <= 0) {
                throw new IllegalArgumentException("timeoutSeconds must be positive");
            }
            return new AtomForgeConfig(this);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AtomForgeConfig)) return false;
        AtomForgeConfig that = (AtomForgeConfig) o;
        return enabled == that.enabled &&
               timeoutSeconds == that.timeoutSeconds &&
               Objects.equals(url, that.url);
    }

    @Override
    public int hashCode() {
        return Objects.hash(url, enabled, timeoutSeconds);
    }

    @Override
    public String toString() {
        return "AtomForgeConfig{" +
               "url='" + url + '\'' +
               ", enabled=" + enabled +
               ", timeoutSeconds=" + timeoutSeconds +
               '}';
    }
}
