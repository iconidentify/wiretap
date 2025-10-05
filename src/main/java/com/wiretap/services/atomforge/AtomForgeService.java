package com.wiretap.services.atomforge;

import com.wiretap.extractor.FrameSummary;

import java.util.concurrent.CompletableFuture;

/**
 * Service interface for AtomForge FDO decompiler integration.
 */
public interface AtomForgeService {

    /**
     * Update the service configuration.
     */
    void configure(AtomForgeConfig config);

    /**
     * Get the current configuration.
     */
    AtomForgeConfig getConfiguration();

    /**
     * Check if AtomForge is available and healthy.
     */
    CompletableFuture<HealthCheckResult> checkHealth();

    /**
     * Decompile a single frame synchronously.
     * Returns decompiled source code or error message.
     */
    String decompileSingleFrame(FrameSummary frame);

    /**
     * Check if the service is currently available based on last health check.
     */
    boolean isAvailable();

    /**
     * Shutdown the service and release resources.
     */
    void shutdown();
}
