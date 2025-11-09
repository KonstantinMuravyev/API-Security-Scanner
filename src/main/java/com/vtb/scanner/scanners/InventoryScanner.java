package com.vtb.scanner.scanners;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.heuristics.EnhancedRules;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * API9:2023 - Improper Inventory Management
 * Проверяет версионирование, deprecated endpoints, документацию
 */
@Slf4j
public class InventoryScanner implements VulnerabilityScanner {
    
    private final String targetUrl;
    
    public InventoryScanner(String targetUrl) {
        this.targetUrl = targetUrl;
    }
    
    @Override
    public List<Vulnerability> scan(OpenAPI openAPI, OpenAPIParser parser) {
        log.info("Запуск Inventory Management Scanner (API9:2023)...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null) {
            return vulnerabilities;
        }
        
        // 1. Проверка версионирования
        vulnerabilities.addAll(checkVersioning(openAPI));
        
        // 2. Проверка deprecated endpoints
        vulnerabilities.addAll(checkDeprecated(openAPI));
        
        // 3. Проверка документации
        vulnerabilities.addAll(checkDocumentation(openAPI));
        
        log.info("Inventory Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkVersioning(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getInfo() == null) {
            return vulnerabilities;
        }
        
        // Проверяем наличие версии
        if (openAPI.getInfo().getVersion() == null || 
            openAPI.getInfo().getVersion().isEmpty()) {
            
            Vulnerability tempVuln = Vulnerability.builder()
                .type(VulnerabilityType.IMPROPER_INVENTORY)
                .severity(Severity.LOW)
                .build();
            
            vulnerabilities.add(Vulnerability.builder()
                .id("INV-NO-VERSION")
                .type(VulnerabilityType.IMPROPER_INVENTORY)
                .severity(Severity.LOW)
                .title("Отсутствует версия API")
                .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    tempVuln, null, false, true)) // evidence=true (точно нет версии)
                .priority(4)
                .description(
                    "В спецификации не указана версия API. " +
                    "Это затрудняет управление изменениями и обратной совместимостью."
                )
                .endpoint("N/A")
                .method("N/A")
                .recommendation(
                    "Укажите версию API в info.version. " +
                    "Используйте семантическое версионирование (semver)."
                )
                .owaspCategory("API9:2023 - Improper Inventory Management")
                .evidence("info.version отсутствует")
                .build());
        }
        
        // Проверяем версионирование в URL
        if (openAPI.getServers() != null) {
            boolean hasVersionInUrl = openAPI.getServers().stream()
                .anyMatch(s -> s.getUrl() != null && 
                        (s.getUrl().contains("/v1") || 
                         s.getUrl().contains("/v2") ||
                         s.getUrl().matches(".*/v\\d+.*")));
            
            if (!hasVersionInUrl) {
                vulnerabilities.add(Vulnerability.builder()
                    .id("INV-NO-URL-VERSION")
                    .type(VulnerabilityType.IMPROPER_INVENTORY)
                    .severity(Severity.INFO)
                    .title("Нет версии в URL")
                    .description(
                        "Server URL не содержит версию API (/v1, /v2 и т.д.). " +
                        "Это best practice для управления версиями."
                    )
                    .endpoint("N/A")
                    .method("N/A")
                    .recommendation(
                        "Включите версию в URL: /api/v1/..., /api/v2/... " +
                        "Это упрощает поддержку нескольких версий одновременно."
                    )
                    .owaspCategory("API9:2023 - Improper Inventory Management")
                    .evidence("Server URL без версии")
                    .build());
            }
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkDeprecated(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // СЕМАНТИКА: определяем важность endpoint по типу операций
            Operation anyOp = pathItem.getGet() != null ? pathItem.getGet() :
                             pathItem.getPost() != null ? pathItem.getPost() : null;
            
            // Проверяем deprecated endpoints
            List<String> deprecatedMethods = new ArrayList<>();
            
            if (pathItem.getGet() != null && Boolean.TRUE.equals(pathItem.getGet().getDeprecated())) {
                deprecatedMethods.add("GET");
            }
            if (pathItem.getPost() != null && Boolean.TRUE.equals(pathItem.getPost().getDeprecated())) {
                deprecatedMethods.add("POST");
            }
            if (pathItem.getPut() != null && Boolean.TRUE.equals(pathItem.getPut().getDeprecated())) {
                deprecatedMethods.add("PUT");
            }
            if (pathItem.getDelete() != null && Boolean.TRUE.equals(pathItem.getDelete().getDeprecated())) {
                deprecatedMethods.add("DELETE");
            }
            
            if (!deprecatedMethods.isEmpty()) {
                // ИСПОЛЬЗУЕМ SmartAnalyzer для контекста!
                int riskScore = anyOp != null ? 
                    com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
                        path, deprecatedMethods.get(0), anyOp, openAPI) : 0;
                Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
                
                // СЕМАНТИКА: deprecated критичные операции = выше severity
                com.vtb.scanner.semantic.OperationClassifier.OperationType opType = 
                    anyOp != null ? com.vtb.scanner.semantic.OperationClassifier.classify(path, "GET", anyOp) :
                    com.vtb.scanner.semantic.OperationClassifier.OperationType.UNKNOWN;
                
                boolean isCritical = (opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.TRANSFER_MONEY ||
                                     opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.PAYMENT ||
                                     opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.ADMIN_ACTION);
                
                // УМНЫЙ расчёт: SmartAnalyzer + семантика
                Severity severity;
                if (isCritical) {
                    severity = (baseSeverity == Severity.CRITICAL || baseSeverity == Severity.HIGH || riskScore > 100) ? 
                        Severity.MEDIUM : Severity.INFO;
                } else {
                    severity = baseSeverity == Severity.CRITICAL || baseSeverity == Severity.HIGH ? 
                        Severity.INFO : Severity.INFO;
                }
                
                // ДИНАМИЧЕСКИЙ расчет!
                Vulnerability tempVuln = Vulnerability.builder()
                    .type(VulnerabilityType.IMPROPER_INVENTORY)
                    .severity(severity)
                    .riskScore(riskScore)
                    .build();
                
                int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    tempVuln, anyOp, false, true); // hasEvidence=true (deprecated=true)
                int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                    tempVuln, confidence);
                
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.IMPROPER_INVENTORY, path, String.join(",", deprecatedMethods), null,
                        "Deprecated endpoint"))
                    .type(VulnerabilityType.IMPROPER_INVENTORY)
                    .severity(severity)
                    .riskScore(riskScore)
                    .confidence(confidence)
                    .priority(priority)
                    .title("Обнаружен deprecated endpoint")
                    .description(String.format(
                        "Эндпоинт %s помечен как deprecated для методов: %s. " +
                        "Убедитесь, что он будет удален в следующей мажорной версии.",
                        path, String.join(", ", deprecatedMethods)
                    ))
                    .endpoint(path)
                    .method(String.join(",", deprecatedMethods))
                    .recommendation(
                        "Deprecated endpoints должны:\n" +
                        "1. Иметь дату удаления\n" +
                        "2. Возвращать Warning header\n" +
                        "3. Документировать альтернативу"
                    )
                    .owaspCategory("API9:2023 - Improper Inventory Management")
                    .evidence("deprecated: true")
                    .build());
            }
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkDocumentation(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Проверяем наличие базовой документации
        if (openAPI.getInfo() == null || 
            openAPI.getInfo().getDescription() == null || 
            openAPI.getInfo().getDescription().isEmpty()) {
            
            vulnerabilities.add(Vulnerability.builder()
                .id("INV-NO-DESCRIPTION")
                .type(VulnerabilityType.IMPROPER_INVENTORY)
                .severity(Severity.INFO)
                .title("Отсутствует описание API")
                .description(
                    "В спецификации нет описания API (info.description). " +
                    "Хорошая документация - важна для безопасности."
                )
                .endpoint("N/A")
                .method("N/A")
                .recommendation(
                    "Добавьте детальное описание API:\n" +
                    "- Цель и назначение\n" +
                    "- Требования аутентификации\n" +
                    "- Rate limits\n" +
                    "- Контактная информация"
                )
                .owaspCategory("API9:2023 - Improper Inventory Management")
                .evidence("info.description пустое")
                .build());
        }
        
        return vulnerabilities;
    }
}

