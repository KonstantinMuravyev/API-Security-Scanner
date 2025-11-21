package com.vtb.scanner.models;

import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class ExecutiveSummary {
    private String riskLevel;
    private int riskScore;
    private String apiContext;
    private LocalDateTime generatedAt;

    private int totalVulnerabilities;
    private int criticalVulnerabilities;
    private int highVulnerabilities;
    private int mediumVulnerabilities;
    private int lowVulnerabilities;
    private int infoVulnerabilities;

    private int criticalExposures;
    private int consentGaps;
    private int unauthorizedFlows;
    private int secretLeaks;
    private int shadowApis;

    @Builder.Default
    private List<String> keyFindings = new ArrayList<>();
    @Builder.Default
    private List<String> recommendedActions = new ArrayList<>();
    @Builder.Default
    private List<TopFinding> topCriticalFindings = new ArrayList<>();
    @Builder.Default
    private Map<String, Long> severityBreakdown = new LinkedHashMap<>();
    @Builder.Default
    private Map<String, Long> priorityBreakdown = new LinkedHashMap<>();

    @Data
    @Builder
    public static class TopFinding {
        private String title;
        private String endpoint;
        private String method;
        private String severity;
        private int priority;
        private int riskScore;
        private int confidence;
        private String type;
    }
}
