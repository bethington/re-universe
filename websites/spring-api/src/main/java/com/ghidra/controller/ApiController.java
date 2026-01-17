package com.ghidra.controller;

import com.ghidra.model.VersionData;
import com.ghidra.model.BinaryData;
import com.ghidra.service.WebDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.CacheManager;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ApiController {

    @Autowired
    private WebDataService webDataService;

    @Autowired
    private CacheManager cacheManager;

    @GetMapping("/versions")
    public ResponseEntity<List<VersionData>> getVersions() {
        try {
            List<VersionData> versions = webDataService.getVersions();
            return ResponseEntity.ok(versions);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/binaries")
    public ResponseEntity<List<BinaryData>> getBinaries(
            @RequestParam String gameType,
            @RequestParam String version) {
        try {
            List<BinaryData> binaries = webDataService.getBinariesForVersion(gameType, version);
            return ResponseEntity.ok(binaries);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        try {
            int executableCount = webDataService.getExecutableCount();
            return ResponseEntity.ok(Map.of(
                "executableCount", executableCount,
                "status", "ok"
            ));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/categories")
    public ResponseEntity<Map<String, Object>> getCategories() {
        try {
            Map<String, Object> categories = webDataService.getCategories();
            return ResponseEntity.ok(categories);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/file-history")
    public ResponseEntity<Map<String, Object>> getFileHistory() {
        try {
            Map<String, Object> fileHistory = webDataService.getFileHistory();
            return ResponseEntity.ok(fileHistory);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/diffs")
    public ResponseEntity<Map<String, Object>> getDiffs() {
        try {
            Map<String, Object> diffs = webDataService.getDiffs();
            return ResponseEntity.ok(diffs);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/exports")
    public ResponseEntity<Map<String, Object>> getExports() {
        try {
            Map<String, Object> exports = webDataService.getExports();
            return ResponseEntity.ok(exports);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/text-content")
    public ResponseEntity<Map<String, Object>> getTextContent() {
        try {
            Map<String, Object> textContent = webDataService.getTextContent();
            return ResponseEntity.ok(textContent);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/functions/index")
    public ResponseEntity<Map<String, Object>> getFunctionIndex() {
        try {
            Map<String, Object> functionIndex = webDataService.getFunctionIndex();
            return ResponseEntity.ok(functionIndex);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Clears all caches. Call this after ingesting new binaries to refresh data.
     * Example: POST /api/cache/clear
     */
    @PostMapping("/cache/clear")
    public ResponseEntity<Map<String, Object>> clearCache() {
        try {
            cacheManager.getCacheNames().forEach(cacheName -> {
                var cache = cacheManager.getCache(cacheName);
                if (cache != null) {
                    cache.clear();
                }
            });
            return ResponseEntity.ok(Map.of(
                "status", "ok",
                "message", "All caches cleared",
                "caches", cacheManager.getCacheNames()
            ));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Returns cache status and statistics.
     */
    @GetMapping("/cache/status")
    public ResponseEntity<Map<String, Object>> getCacheStatus() {
        return ResponseEntity.ok(Map.of(
            "status", "ok",
            "caches", cacheManager.getCacheNames(),
            "cacheType", "ConcurrentMapCache (in-memory)"
        ));
    }

    /**
     * Lightweight health check endpoint that doesn't depend on external services.
     * Returns basic application status and build info.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "application", "BSim Analysis API",
            "version", "1.0.0",
            "timestamp", java.time.Instant.now().toString(),
            "checks", Map.of(
                "app", "UP",
                "jvm", "UP"
            )
        ));
    }
}
