package com.vtb.scanner.models;

import lombok.Data;
import lombok.Builder;
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

