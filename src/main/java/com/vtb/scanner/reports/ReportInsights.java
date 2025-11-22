package com.vtb.scanner.reports;

import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Общие аналитические утилиты для отчетов (HTML, PDF, CLI, JSON).
 */
public final class ReportInsights {

    private static final Set<VulnerabilityType> CORE_RISK_TYPES = Set.of(
        VulnerabilityType.COMMAND_INJECTION,
        VulnerabilityType.SQL_INJECTION,
        VulnerabilityType.NOSQL_INJECTION,
        VulnerabilityType.LDAP_INJECTION,
        VulnerabilityType.SSRF,
        VulnerabilityType.BOLA,
        VulnerabilityType.BFLA,
        VulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
        VulnerabilityType.BROKEN_AUTHENTICATION,
        VulnerabilityType.SENSITIVE_DATA_IN_URL,
        VulnerabilityType.SECURITY_MISCONFIGURATION
    );

    private ReportInsights() {
        // utility
    }

    /**
     * Возвращает отсортированный список критичных уязвимостей без дубликатов (endpoint+method+type).
     */
    public static List<Vulnerability> getTopCriticalVulnerabilities(List<Vulnerability> vulnerabilities) {
        return getTopCriticalVulnerabilities(vulnerabilities, null);
    }

    public static List<Vulnerability> getTopCriticalVulnerabilities(List<Vulnerability> vulnerabilities,
                                                                    String apiContext) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return List.of();
        }

        List<Vulnerability> filtered = new ArrayList<>();
        for (Vulnerability vuln : vulnerabilities) {
            if (vuln == null || vuln.getType() == null || vuln.getSeverity() == null) {
                continue;
            }
            if (shouldConsiderForTopFindings(vuln, apiContext)) {
                filtered.add(vuln);
            }
        }

        if (filtered.isEmpty()) {
            return List.of();
        }

        Map<String, Vulnerability> dedup = new LinkedHashMap<>();
        for (Vulnerability vuln : filtered) {
            String key = String.format("%s|%s|%s",
                vuln.getEndpoint() != null ? vuln.getEndpoint() : "",
                vuln.getMethod() != null ? vuln.getMethod() : "",
                vuln.getType().name());

            dedup.merge(key, vuln, (existing, candidate) -> chooseHigherImpact(existing, candidate));
        }

        List<Vulnerability> sorted = new ArrayList<>(dedup.values());
        sorted.sort((a, b) -> {
            int priorityCompare = Integer.compare(a.getPriority(), b.getPriority());
            if (priorityCompare != 0) {
                return priorityCompare;
            }
            int severityCompare = Integer.compare(severityWeight(b.getSeverity()), severityWeight(a.getSeverity()));
            if (severityCompare != 0) {
                return severityCompare;
            }
            int riskCompare = Integer.compare(b.getRiskScore(), a.getRiskScore());
            if (riskCompare != 0) {
                return riskCompare;
            }
            int confidenceCompare = Integer.compare(b.getConfidence(), a.getConfidence());
            if (confidenceCompare != 0) {
                return confidenceCompare;
            }
            String titleA = a.getTitle() != null ? a.getTitle() : "";
            String titleB = b.getTitle() != null ? b.getTitle() : "";
            return titleA.compareToIgnoreCase(titleB);
        });

        return sorted;
    }

    private static boolean shouldConsiderForTopFindings(Vulnerability vulnerability, String apiContext) {
        VulnerabilityType type = vulnerability.getType();
        Severity severity = vulnerability.getSeverity();

        if (severity == Severity.CRITICAL) {
            return true;
        }

        if (type == VulnerabilityType.BOLA || type == VulnerabilityType.BFLA
            || type == VulnerabilityType.EXCESSIVE_DATA_EXPOSURE
            || type == VulnerabilityType.BROKEN_AUTHENTICATION) {
            return severity == Severity.HIGH;
        }

        if (type == VulnerabilityType.SECURITY_MISCONFIGURATION) {
            if (severity == Severity.HIGH && isSensitiveContext(apiContext)) {
                return true;
            }
            return false;
        }

        if (CORE_RISK_TYPES.contains(type)) {
            return severity == Severity.HIGH || severity == Severity.MEDIUM;
        }

        return false;
    }

    private static boolean isSensitiveContext(String apiContext) {
        if (apiContext == null) {
            return false;
        }
        String normalized = apiContext.toLowerCase();
        return normalized.contains("bank") || normalized.contains("банк") ||
            normalized.contains("gov") || normalized.contains("gosuslugi") ||
            normalized.contains("health") || normalized.contains("медиц") ||
            normalized.contains("telecom") || normalized.contains("авто");
    }

    private static Vulnerability chooseHigherImpact(Vulnerability existing, Vulnerability candidate) {
        if (candidate == null) {
            return existing;
        }
        if (existing == null) {
            return candidate;
        }
        if (candidate.getPriority() < existing.getPriority()) {
            return candidate;
        }
        if (candidate.getPriority() > existing.getPriority()) {
            return existing;
        }
        int severityCompare = Integer.compare(severityWeight(candidate.getSeverity()), severityWeight(existing.getSeverity()));
        if (severityCompare > 0) {
            return candidate;
        }
        if (severityCompare < 0) {
            return existing;
        }
        if (candidate.getRiskScore() > existing.getRiskScore()) {
            return candidate;
        }
        if (candidate.getRiskScore() < existing.getRiskScore()) {
            return existing;
        }
        return candidate.getConfidence() >= existing.getConfidence() ? candidate : existing;
    }

    private static int severityWeight(Severity severity) {
        if (severity == null) {
            return -1;
        }
        return switch (severity) {
            case CRITICAL -> 5;
            case HIGH -> 4;
            case MEDIUM -> 3;
            case LOW -> 2;
            case INFO -> 1;
        };
    }
}
