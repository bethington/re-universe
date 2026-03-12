package com.ghidra.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Service
public class KnowledgeIntegrationService {

    private final WebClient webClient;

    @Value("${knowledge.integration.url:http://knowledge-integration:8095}")
    private String knowledgeIntegrationUrl;

    public KnowledgeIntegrationService() {
        this.webClient = WebClient.builder()
            .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(1024 * 1024)) // 1MB buffer
            .build();
    }

    /**
     * Get function insights from Knowledge DB
     */
    @Cacheable("functionInsights")
    public Map<String, Object> getFunctionInsights(Long functionId) {
        try {
            return webClient.get()
                .uri(knowledgeIntegrationUrl + "/function/{functionId}/insights", functionId)
                .retrieve()
                .bodyToMono(Map.class)
                .onErrorReturn(Map.of(
                    "error", "Knowledge service unavailable",
                    "functionId", functionId,
                    "insights", List.of()
                ))
                .block();

        } catch (Exception e) {
            System.out.println("DEBUG: Knowledge service error for function " + functionId + ": " + e.getMessage());
            return Map.of(
                "error", "Knowledge service error: " + e.getMessage(),
                "functionId", functionId,
                "insights", List.of()
            );
        }
    }

    /**
     * Get integration statistics
     */
    @Cacheable("knowledgeStats")
    public Map<String, Object> getKnowledgeStats() {
        try {
            return webClient.get()
                .uri(knowledgeIntegrationUrl + "/stats")
                .retrieve()
                .bodyToMono(Map.class)
                .onErrorReturn(Map.of(
                    "error", "Knowledge service unavailable",
                    "total_functions_analyzed", 0,
                    "functions_with_insights", 0
                ))
                .block();

        } catch (Exception e) {
            System.out.println("DEBUG: Knowledge stats error: " + e.getMessage());
            return Map.of(
                "error", "Knowledge service error: " + e.getMessage(),
                "total_functions_analyzed", 0,
                "functions_with_insights", 0
            );
        }
    }

    /**
     * Trigger analysis for a specific function
     */
    public Map<String, Object> triggerFunctionAnalysis(Long functionId) {
        try {
            return webClient.post()
                .uri(knowledgeIntegrationUrl + "/function/{functionId}/analyze", functionId)
                .retrieve()
                .bodyToMono(Map.class)
                .onErrorReturn(Map.of(
                    "error", "Failed to trigger analysis",
                    "functionId", functionId
                ))
                .block();

        } catch (Exception e) {
            System.out.println("DEBUG: Failed to trigger analysis for function " + functionId + ": " + e.getMessage());
            return Map.of(
                "error", "Analysis trigger failed: " + e.getMessage(),
                "functionId", functionId
            );
        }
    }

    /**
     * Get bridge status
     */
    public Map<String, Object> getBridgeStatus() {
        try {
            return webClient.get()
                .uri(knowledgeIntegrationUrl + "/bridge/status")
                .retrieve()
                .bodyToMono(Map.class)
                .onErrorReturn(Map.of(
                    "error", "Bridge status unavailable",
                    "bridge_initialized", false,
                    "database_connected", false
                ))
                .block();

        } catch (Exception e) {
            return Map.of(
                "error", "Bridge status error: " + e.getMessage(),
                "bridge_initialized", false,
                "database_connected", false
            );
        }
    }

    /**
     * Check if Knowledge Integration service is healthy
     */
    public boolean isKnowledgeServiceHealthy() {
        try {
            Map<String, Object> health = webClient.get()
                .uri(knowledgeIntegrationUrl + "/health")
                .retrieve()
                .bodyToMono(Map.class)
                .block();

            return health != null && "healthy".equals(health.get("status"));

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get enhanced function data with knowledge insights
     */
    public Map<String, Object> getEnhancedFunctionData(Long functionId, String functionName) {
        Map<String, Object> result = Map.of(
            "functionId", functionId,
            "functionName", functionName != null ? functionName : "Unknown",
            "knowledgeAvailable", false,
            "insights", List.of(),
            "analysisTriggered", false
        );

        try {
            // Get existing insights
            Map<String, Object> insights = getFunctionInsights(functionId);
            boolean hasInsights = insights.containsKey("insights") &&
                !((List<?>) insights.get("insights")).isEmpty();

            // If no insights and service is healthy, trigger analysis
            boolean analysisTriggered = false;
            if (!hasInsights && isKnowledgeServiceHealthy()) {
                Map<String, Object> triggerResult = triggerFunctionAnalysis(functionId);
                analysisTriggered = !triggerResult.containsKey("error");
            }

            return Map.of(
                "functionId", functionId,
                "functionName", functionName != null ? functionName : "Unknown",
                "knowledgeAvailable", hasInsights,
                "insights", insights.getOrDefault("insights", List.of()),
                "analysisTriggered", analysisTriggered,
                "metadata", Map.of(
                    "serviceHealthy", isKnowledgeServiceHealthy(),
                    "lastChecked", java.time.Instant.now().toString()
                )
            );

        } catch (Exception e) {
            System.out.println("DEBUG: Enhanced function data error for " + functionId + ": " + e.getMessage());
            return result;
        }
    }
}