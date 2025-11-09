package com.vtb.scanner.benchmark;

import com.vtb.scanner.models.ScanResult;
import com.vtb.scanner.models.Severity;
import lombok.Data;

/**
 * Сравнение результатов с industry benchmarks
 * Дает контекст - это много или мало уязвимостей?
 */
public class BenchmarkComparator {
    
    // Industry averages (на основе исследований)
    private static final double AVG_VULNS_PER_ENDPOINT = 2.5;
    private static final double AVG_CRITICAL_PERCENTAGE = 15.0;
    private static final double AVG_HIGH_PERCENTAGE = 25.0;
    
    // Best practice benchmarks
    private static final int BEST_PRACTICE_MAX_CRITICAL = 0;
    private static final int BEST_PRACTICE_MAX_HIGH = 2;
    private static final int BEST_PRACTICE_MAX_TOTAL = 10;
    
    /**
     * Сравнить результаты с benchmarks
     */
    public static BenchmarkComparison compare(ScanResult result) {
        BenchmarkComparison comparison = new BenchmarkComparison();
        
        int totalEndpoints = result.getStatistics().getTotalEndpoints();
        int totalVulns = result.getVulnerabilities().size();
        int critical = result.getVulnerabilityCountBySeverity(Severity.CRITICAL);
        int high = result.getVulnerabilityCountBySeverity(Severity.HIGH);
        
        // 1. Сравнение с industry average
        double vulnsPerEndpoint = totalEndpoints > 0 ? (double) totalVulns / totalEndpoints : 0;
        comparison.setVulnsPerEndpoint(vulnsPerEndpoint);
        comparison.setIndustryAvgVulnsPerEndpoint(AVG_VULNS_PER_ENDPOINT);
        
        if (vulnsPerEndpoint > AVG_VULNS_PER_ENDPOINT * 1.5) {
            comparison.setVulnsDensity("КРИТИЧНО ВЫСОКАЯ (в 1.5+ раз выше среднего)");
            comparison.setVulnsDensityScore(0);
        } else if (vulnsPerEndpoint > AVG_VULNS_PER_ENDPOINT) {
            comparison.setVulnsDensity("Выше среднего");
            comparison.setVulnsDensityScore(40);
        } else if (vulnsPerEndpoint > AVG_VULNS_PER_ENDPOINT * 0.5) {
            comparison.setVulnsDensity("Средний уровень");
            comparison.setVulnsDensityScore(70);
        } else {
            comparison.setVulnsDensity("Лучше среднего!");
            comparison.setVulnsDensityScore(90);
        }
        
        // 2. Сравнение с best practice
        comparison.setBestPracticeMaxCritical(BEST_PRACTICE_MAX_CRITICAL);
        comparison.setBestPracticeMaxHigh(BEST_PRACTICE_MAX_HIGH);
        comparison.setBestPracticeMaxTotal(BEST_PRACTICE_MAX_TOTAL);
        
        int bpScore = 100;
        bpScore -= Math.min(critical * 20, 100); // -20 за каждый CRITICAL
        bpScore -= Math.min(high * 10, 50);       // -10 за каждый HIGH
        bpScore = Math.max(0, bpScore);
        
        comparison.setBestPracticeScore(bpScore);
        
        if (bpScore >= 90) {
            comparison.setBestPracticeLevel("🏆 ОТЛИЧНО - соответствует best practice");
        } else if (bpScore >= 70) {
            comparison.setBestPracticeLevel("ХОРОШО - небольшие улучшения нужны");
        } else if (bpScore >= 50) {
            comparison.setBestPracticeLevel("УДОВЛЕТВОРИТЕЛЬНО - требуются улучшения");
        } else {
            comparison.setBestPracticeLevel("ПЛОХО - критические проблемы безопасности");
        }
        
        // 3. ГОСТ compliance score
        long gostViolations = result.getVulnerabilities().stream()
            .filter(v -> v.isGostRelated())
            .count();
        
        int gostScore = 100 - (int) Math.min(gostViolations * 20, 100);
        comparison.setGostComplianceScore(gostScore);
        
        if (gostScore >= 90) {
            comparison.setGostComplianceLevel("ОТЛИЧНО - соответствует ГОСТ");
        } else if (gostScore >= 70) {
            comparison.setGostComplianceLevel("ХОРОШО - мелкие доработки");
        } else {
            comparison.setGostComplianceLevel("ТРЕБУЕТСЯ ДОРАБОТКА");
        }
        
        // 4. Общий Security Score (0-100)
        int securityScore = (comparison.getVulnsDensityScore() + bpScore + gostScore) / 3;
        comparison.setOverallSecurityScore(securityScore);
        
        if (securityScore >= 80) {
            comparison.setOverallRating("🏆 ОТЛИЧНАЯ безопасность");
        } else if (securityScore >= 60) {
            comparison.setOverallRating("ХОРОШАЯ безопасность");
        } else if (securityScore >= 40) {
            comparison.setOverallRating("СРЕДНЯЯ безопасность - требуются улучшения");
        } else {
            comparison.setOverallRating("НИЗКАЯ безопасность - КРИТИЧНО!");
        }
        
        return comparison;
    }
    
    @Data
    public static class BenchmarkComparison {
        // Метрики
        private double vulnsPerEndpoint;
        private double industryAvgVulnsPerEndpoint;
        private String vulnsDensity;
        private int vulnsDensityScore;
        
        // Best practice
        private int bestPracticeMaxCritical;
        private int bestPracticeMaxHigh;
        private int bestPracticeMaxTotal;
        private int bestPracticeScore;
        private String bestPracticeLevel;
        
        // ГОСТ
        private int gostComplianceScore;
        private String gostComplianceLevel;
        
        // Общая оценка
        private int overallSecurityScore;
        private String overallRating;
    }
}

