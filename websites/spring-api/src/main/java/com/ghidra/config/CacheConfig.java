package com.ghidra.config;

import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Cache configuration for the Ghidra Analysis API.
 * 
 * Uses in-memory ConcurrentMapCache for simplicity and performance.
 * Data rarely changes (only when new binaries are ingested), so
 * long-lived caches are appropriate.
 * 
 * Cache names:
 * - "versions" - List of all game versions
 * - "binaries" - Binaries for a specific version (keyed by gameType + version)
 * - "folders" - Complete folder structure
 * - "categories" - File category definitions
 * - "functions" - Function data per executable
 * - "functionIndex" - Index of all executables with functions
 * - "crossVersionFunctions" - Cross-version function matrix data
 * - "bsimCrossVersionFunctions" - BSim-enhanced cross-version function data with similarity scores
 */
@Configuration
@EnableCaching
public class CacheConfig {

    @Bean
    @Primary
    public CacheManager cacheManager() {
        return new ConcurrentMapCacheManager(
            "versions",
            "binaries",
            "categories",
            "fileHistory",
            "diffs",
            "exports",
            "textContent",
            "functions",
            "functionIndex",
            "crossVersionFunctions",
            "crossVersionAnalysis",
            "bsimCrossVersionFunctions"
        );
    }
}
