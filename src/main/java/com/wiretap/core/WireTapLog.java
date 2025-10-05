package com.wiretap.core;

/**
 * Centralized logging utility for WireTap.
 * All logging is disabled by default and can be enabled with the --verbose flag.
 */
public final class WireTapLog {
    private static boolean VERBOSE = false;

    private WireTapLog() {
        // Utility class
    }

    /**
     * Enable or disable verbose logging.
     */
    public static void setVerbose(boolean verbose) {
        VERBOSE = verbose;
    }

    /**
     * Check if verbose logging is enabled.
     */
    public static boolean isVerbose() {
        return VERBOSE;
    }

    /**
     * Log an informational message (only if verbose mode is enabled).
     */
    public static void info(String msg) {
        if (VERBOSE) {
            System.out.println("[INFO] " + msg);
        }
    }

    /**
     * Log a debug message (only if verbose mode is enabled).
     */
    public static void debug(String msg) {
        if (VERBOSE) {
            System.out.println("[DEBUG] " + msg);
        }
    }

    /**
     * Log a warning message (only if verbose mode is enabled).
     */
    public static void warn(String msg) {
        if (VERBOSE) {
            System.err.println("[WARN] " + msg);
        }
    }

    /**
     * Log an error message with optional exception (only if verbose mode is enabled).
     */
    public static void error(String msg, Throwable t) {
        if (VERBOSE) {
            System.err.println("[ERROR] " + msg);
            if (t != null) {
                t.printStackTrace(System.err);
            }
        }
    }

    /**
     * Log an error message without exception (only if verbose mode is enabled).
     */
    public static void error(String msg) {
        error(msg, null);
    }
}
