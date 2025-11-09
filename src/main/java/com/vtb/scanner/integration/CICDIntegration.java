package com.vtb.scanner.integration;

import com.vtb.scanner.models.ScanResult;
import com.vtb.scanner.models.Severity;
import lombok.extern.slf4j.Slf4j;

/**
 * Интеграция с CI/CD системами
 * GitHub Actions, GitLab CI и т.д.
 */
@Slf4j
public class CICDIntegration {
    
    /**
     * Определить exit code на основе результатов сканирования
     * 
     * @param result результат сканирования
     * @param failOnHigh прерывать ли сборку при HIGH уязвимостях
     * @return exit code (0 = успех, 1 = провал)
     */
    public static int getExitCode(ScanResult result, boolean failOnHigh) {
        // КРИТИЧНО: Защита от NPE
        if (result == null) {
            log.warn("Результат сканирования null, возвращаем код успеха");
            return 0;
        }
        
        if (result.hasCriticalVulnerabilities()) {
            log.error("Обнаружены CRITICAL уязвимости. Сборка провалена.");
            return 1;
        }
        
        if (failOnHigh && result.getVulnerabilityCountBySeverity(Severity.HIGH) > 0) {
            log.error("Обнаружены HIGH уязвимости. Сборка провалена.");
            return 1;
        }
        
        log.info("Критичных уязвимостей не обнаружено");
        return 0;
    }
    
    /**
     * Вывести краткую сводку для CI/CD
     */
    public static void printCISummary(ScanResult result) {
        // КРИТИЧНО: Защита от NPE
        if (result == null) {
            log.warn("Результат сканирования null, пропускаем вывод");
            return;
        }
        
        System.out.println("\n=== API Security Scan Summary ===");
        System.out.println("API: " + (result.getApiName() != null ? result.getApiName() : "Unknown") + 
                         " v" + (result.getApiVersion() != null ? result.getApiVersion() : "Unknown"));
        System.out.println("Scan Date: " + (result.getScanTimestamp() != null ? result.getScanTimestamp() : "N/A"));
        System.out.println("\nVulnerabilities:");
        
        // Безопасный доступ к методам
        int critical = result.getVulnerabilities() != null ? 
            result.getVulnerabilityCountBySeverity(Severity.CRITICAL) : 0;
        int high = result.getVulnerabilities() != null ? 
            result.getVulnerabilityCountBySeverity(Severity.HIGH) : 0;
        int medium = result.getVulnerabilities() != null ? 
            result.getVulnerabilityCountBySeverity(Severity.MEDIUM) : 0;
        int low = result.getVulnerabilities() != null ? 
            result.getVulnerabilityCountBySeverity(Severity.LOW) : 0;
        int info = result.getVulnerabilities() != null ? 
            result.getVulnerabilityCountBySeverity(Severity.INFO) : 0;
        
        System.out.println("  CRITICAL: " + critical);
        System.out.println("  HIGH:     " + high);
        System.out.println("  MEDIUM:   " + medium);
        System.out.println("  LOW:      " + low);
        System.out.println("  INFO:     " + info);
        System.out.println("\nTotal: " + (result.getVulnerabilities() != null ? result.getVulnerabilities().size() : 0) + " vulnerabilities");
        System.out.println("Contract Violations: " + (result.getContractViolations() != null ? result.getContractViolations().size() : 0));
        System.out.println("Scan Duration: " + (result.getStatistics() != null ? result.getStatistics().getScanDurationMs() : 0) + " ms");
        System.out.println("================================\n");
    }
    
    /**
     * Создать аннотации для GitHub Actions
     */
    public static void printGitHubAnnotations(ScanResult result) {
        // КРИТИЧНО: Защита от NPE
        if (result == null || result.getVulnerabilities() == null) {
            return;
        }
        
        for (var vuln : result.getVulnerabilities()) {
            if (vuln == null) continue;
            
            String level = switch (vuln.getSeverity() != null ? vuln.getSeverity() : Severity.INFO) {
                case CRITICAL, HIGH -> "error";
                case MEDIUM -> "warning";
                default -> "notice";
            };
            
            String endpoint = vuln.getEndpoint() != null ? vuln.getEndpoint() : "N/A";
            String method = vuln.getMethod() != null ? vuln.getMethod() : "N/A";
            String type = vuln.getType() != null ? vuln.getType().name() : "UNKNOWN";
            String title = vuln.getTitle() != null ? vuln.getTitle() : "Vulnerability";
            
            System.out.printf("::%s file=API,title=%s::%s [%s] - %s%n",
                level, type, endpoint, method, title
            );
        }
    }
}

