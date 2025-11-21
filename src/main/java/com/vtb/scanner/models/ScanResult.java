package com.vtb.scanner.models;

import com.vtb.scanner.dynamic.DynamicScanReport;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Результат сканирования API
 */
@Data
@Builder
public class ScanResult {
    private String apiName;
    private String apiVersion;
    private String targetUrl;
    private LocalDateTime scanTimestamp;
    
    @Builder.Default
    private List<Vulnerability> vulnerabilities = new ArrayList<>();
    
    @Builder.Default
    private List<ContractViolation> contractViolations = new ArrayList<>();
    
    private ScanStatistics statistics;
    
    // Дополнительная информация для тестов
    private String apiContext; // BANKING, HEALTHCARE, etc.
    private long apiHealthScore; // 0-100
    
    @Builder.Default
    private AttackSurfaceSummary attackSurface = AttackSurfaceSummary.builder().build();
    @Builder.Default
    private ThreatGraph threatGraph = ThreatGraph.builder().build();
    @Builder.Default
    private DataProtectionSummary dataProtection = DataProtectionSummary.builder().build();
    private int overallRiskScore;
    private String riskLevel;
    @Builder.Default
    private List<String> keyFindings = new ArrayList<>();
    @Builder.Default
    private ExecutiveSummary executiveSummary = ExecutiveSummary.builder().build();
    @Builder.Default
    private DynamicScanReport dynamicScanReport = DynamicScanReport.empty();
    
    /**
     * Получить количество уязвимостей по критичности
     */
    public int getVulnerabilityCountBySeverity(Severity severity) {
        return (int) vulnerabilities.stream()
            .filter(v -> v.getSeverity() == severity)
            .count();
    }
    
    /**
     * Есть ли критичные уязвимости
     */
    public boolean hasCriticalVulnerabilities() {
        return vulnerabilities.stream()
            .anyMatch(v -> v.getSeverity() == Severity.CRITICAL || v.getSeverity() == Severity.HIGH);
    }
}

