package com.ghidra.controller;

import com.ghidra.model.VersionData;
import com.ghidra.model.BinaryData;
import com.ghidra.service.WebDataService;
import com.ghidra.service.KnowledgeIntegrationService;
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

    @Autowired
    private KnowledgeIntegrationService knowledgeIntegrationService;

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
        System.out.println("DEBUG CONTROLLER: getBinaries called with gameType=" + gameType + ", version=" + version);
        try {
            List<BinaryData> binaries = webDataService.getBinariesForVersion(gameType, version);
            System.out.println("DEBUG CONTROLLER: Service returned " + binaries.size() + " binaries");
            return ResponseEntity.ok(binaries);
        } catch (Exception e) {
            System.out.println("DEBUG CONTROLLER: Exception occurred: " + e.getMessage());
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
     * Get cross-version function data for a specific binary file.
     * Returns function addresses across all versions of the binary.
     * Example: GET /api/functions/cross-version/D2Client.dll
     */
    @GetMapping("/functions/cross-version/{filename}")
    public ResponseEntity<Map<String, Object>> getCrossVersionFunctions(
            @PathVariable String filename) {
        System.out.println("DEBUG: getCrossVersionFunctions (fallback) called with filename=" + filename);
        try {
            Map<String, Object> response = webDataService.getCrossVersionFunctions(filename);

            if (response.containsKey("error")) {
                System.out.println("DEBUG: Service returned error: " + response.get("error"));
                return ResponseEntity.internalServerError().body(response);
            }

            // Add metadata expected by website
            response.put("usedBSim", false); // Fallback endpoint doesn't use BSim
            response.put("isExe", filename.toLowerCase().endsWith(".exe"));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            System.out.println("DEBUG: Exception in getCrossVersionFunctions: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Get BSim-enhanced cross-version function data for a specific version and binary file.
     * Returns function addresses with similarity scores across all versions.
     * Example: GET /api/functions/cross-version/1.00/D2Client.dll
     * Website expects: /functions/cross-version/{version}/{filename}?threshold=0.6
     */
    @GetMapping("/functions/cross-version/{version}/{filename}")
    public ResponseEntity<Map<String, Object>> getBSimCrossVersionFunctions(
            @PathVariable String version,
            @PathVariable String filename,
            @RequestParam(defaultValue = "0.6") double threshold,
            @RequestParam(defaultValue = "false") Boolean include_details) {
        System.out.println("DEBUG CONTROLLER: getBSimCrossVersionFunctions called with version=" + version + ", filename=" + filename + ", threshold=" + threshold);
        try {
            Map<String, Object> response = webDataService.getBSimCrossVersionFunctions(
                version, filename, threshold);

            System.out.println("DEBUG CONTROLLER: Service returned: " + (response.containsKey("error") ? "ERROR - " + response.get("error") : "SUCCESS"));

            if (response.containsKey("error")) {
                return ResponseEntity.internalServerError().body(response);
            }

            // Add additional metadata expected by website
            response.put("usedBSim", true);
            response.put("isExe", filename.toLowerCase().endsWith(".exe"));

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            System.out.println("DEBUG CONTROLLER: Exception occurred: " + e.getMessage());
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

    // ========================================================================
    // KNOWLEDGE INTEGRATION ENDPOINTS
    // ========================================================================

    /**
     * Get function insights from Knowledge DB
     * Example: GET /api/functions/12345/insights
     */
    @GetMapping("/functions/{functionId}/insights")
    public ResponseEntity<Map<String, Object>> getFunctionInsights(@PathVariable Long functionId) {
        try {
            Map<String, Object> insights = knowledgeIntegrationService.getFunctionInsights(functionId);
            return ResponseEntity.ok(insights);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.ok(Map.of(
                "error", "Failed to retrieve insights",
                "functionId", functionId,
                "insights", List.of()
            ));
        }
    }

    /**
     * Get enhanced function data with knowledge insights
     * Example: GET /api/functions/12345/enhanced?name=MyFunction
     */
    @GetMapping("/functions/{functionId}/enhanced")
    public ResponseEntity<Map<String, Object>> getEnhancedFunctionData(
            @PathVariable Long functionId,
            @RequestParam(required = false) String name) {
        try {
            Map<String, Object> enhanced = knowledgeIntegrationService
                .getEnhancedFunctionData(functionId, name);
            return ResponseEntity.ok(enhanced);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.ok(Map.of(
                "functionId", functionId,
                "functionName", name != null ? name : "Unknown",
                "knowledgeAvailable", false,
                "insights", List.of(),
                "error", "Enhancement failed: " + e.getMessage()
            ));
        }
    }

    /**
     * Trigger knowledge analysis for a function
     * Example: POST /api/functions/12345/analyze
     */
    @PostMapping("/functions/{functionId}/analyze")
    public ResponseEntity<Map<String, Object>> triggerFunctionAnalysis(@PathVariable Long functionId) {
        try {
            Map<String, Object> result = knowledgeIntegrationService.triggerFunctionAnalysis(functionId);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.ok(Map.of(
                "error", "Failed to trigger analysis",
                "functionId", functionId,
                "message", e.getMessage()
            ));
        }
    }

    /**
     * Get Knowledge Integration statistics
     * Example: GET /api/knowledge/stats
     */
    @GetMapping("/knowledge/stats")
    public ResponseEntity<Map<String, Object>> getKnowledgeStats() {
        try {
            Map<String, Object> stats = knowledgeIntegrationService.getKnowledgeStats();
            return ResponseEntity.ok(stats);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.ok(Map.of(
                "error", "Failed to retrieve knowledge stats",
                "message", e.getMessage()
            ));
        }
    }

    /**
     * Get Knowledge Bridge status
     * Example: GET /api/knowledge/bridge/status
     */
    @GetMapping("/knowledge/bridge/status")
    public ResponseEntity<Map<String, Object>> getKnowledgeBridgeStatus() {
        try {
            Map<String, Object> status = knowledgeIntegrationService.getBridgeStatus();
            return ResponseEntity.ok(status);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.ok(Map.of(
                "error", "Failed to get bridge status",
                "bridge_initialized", false,
                "database_connected", false,
                "message", e.getMessage()
            ));
        }
    }

    // ========================================================================
    // HEALTH CHECK
    // ========================================================================

    /**
     * Comprehensive health check including Knowledge DB integration
     * Returns detailed application status and service connectivity.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        boolean knowledgeHealthy = knowledgeIntegrationService.isKnowledgeServiceHealthy();

        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "application", "BSim Analysis API with Knowledge Integration",
            "version", "1.0.0",
            "timestamp", java.time.Instant.now().toString(),
            "checks", Map.of(
                "app", "UP",
                "jvm", "UP",
                "knowledge_integration", knowledgeHealthy ? "UP" : "DOWN"
            ),
            "features", Map.of(
                "knowledge_insights", knowledgeHealthy,
                "function_analysis", knowledgeHealthy,
                "bridge_integration", true
            )
        ));
    }
}
