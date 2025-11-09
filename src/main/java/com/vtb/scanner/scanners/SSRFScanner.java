package com.vtb.scanner.scanners;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.regex.Pattern;

/**
 * API7:2023 - Server Side Request Forgery (SSRF)
 * Проверяет параметры, которые могут использоваться для SSRF атак
 */
@Slf4j
public class SSRFScanner implements VulnerabilityScanner {
    
    private final String targetUrl;
    
    // Паттерны опасных параметров для SSRF
    private static final Pattern SSRF_PATTERN = Pattern.compile(
        ".*(url|uri|link|href|redirect|callback|webhook|proxy|fetch|download|import|source|src).*",
        Pattern.CASE_INSENSITIVE
    );
    
    public SSRFScanner(String targetUrl) {
        this.targetUrl = targetUrl;
    }
    
    @Override
    public List<Vulnerability> scan(OpenAPI openAPI, OpenAPIParser parser) {
        log.info("Запуск SSRF Scanner (API7:2023)...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            if (pathItem.getGet() != null) {
                vulnerabilities.addAll(checkSSRF(path, "GET", pathItem.getGet(), openAPI));
            }
            if (pathItem.getPost() != null) {
                vulnerabilities.addAll(checkSSRF(path, "POST", pathItem.getPost(), openAPI));
            }
            if (pathItem.getPut() != null) {
                vulnerabilities.addAll(checkSSRF(path, "PUT", pathItem.getPut(), openAPI));
            }
            if (pathItem.getPatch() != null) {
                vulnerabilities.addAll(checkSSRF(path, "PATCH", pathItem.getPatch(), openAPI));
            }
        }
        
        log.info("SSRF Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkSSRF(String path, String method, Operation operation, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (operation.getParameters() == null) {
            return vulnerabilities;
        }
        
        // ИСПОЛЬЗУЕМ SmartAnalyzer для контекста!
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
            path, method, operation, openAPI);
        Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
        
        // СЕМАНТИКА: определяем тип операции
        com.vtb.scanner.semantic.OperationClassifier.OperationType opType = 
            com.vtb.scanner.semantic.OperationClassifier.classify(path, method, operation);
        
        for (Parameter param : operation.getParameters()) {
            String paramName = param.getName();
            
            // ИСПОЛЬЗУЕМ EnhancedRules вместо хардкода!
            if (com.vtb.scanner.heuristics.EnhancedRules.isSSRFRisk(param)) {
                boolean hasValidation = hasUrlValidation(param);
                
                // УМНЫЙ расчёт severity: SmartAnalyzer + семантика + валидация
                Severity severity;
                if (opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.ADMIN_ACTION) {
                    // Админские операции - критичнее!
                    severity = (baseSeverity == Severity.CRITICAL || riskScore > 120) ? 
                        Severity.CRITICAL : (hasValidation ? Severity.HIGH : Severity.CRITICAL);
                } else {
                    // Обычные операции - используем SmartAnalyzer + валидацию
                    if (hasValidation) {
                        severity = switch(baseSeverity) {
                            case CRITICAL -> Severity.HIGH;
                            case HIGH -> Severity.MEDIUM;
                            default -> baseSeverity;
                        };
                    } else {
                        severity = switch(baseSeverity) {
                            case INFO, LOW -> Severity.MEDIUM;
                            case MEDIUM -> Severity.HIGH;
                            case HIGH, CRITICAL -> baseSeverity;
                        };
                    }
                }
                
                // ДИНАМИЧЕСКИЙ расчет confidence!
                Vulnerability tempVuln = Vulnerability.builder()
                    .type(VulnerabilityType.SSRF)
                    .severity(severity)
                    .riskScore(riskScore)
                    .build();
                
                int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    tempVuln, operation, false, true); // hasEvidence=true (EnhancedRules нашли!)
                
                // Если есть валидация - снижаем
                if (hasValidation) {
                    confidence = Math.max(50, confidence - 20);
                }
                
                int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                    tempVuln, confidence);
                
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.SSRF, path, method, paramName,
                        "SSRF risk in parameter"))
                    .type(VulnerabilityType.SSRF)
                    .severity(severity)
                    .title("Возможна SSRF уязвимость")
                    .description(String.format(
                        "Параметр '%s' в %s %s принимает URL. " +
                        "Тип операции: %s\n" +
                        "Если не валидируется, злоумышленник может заставить сервер " +
                        "делать запросы к внутренним ресурсам (localhost, 192.168.x.x, AWS metadata и т.д.)",
                        paramName, method, path, opType
                    ))
                    .endpoint(path)
                    .method(method)
                    .recommendation(
                        "1. Используйте whitelist допустимых доменов/протоколов\n" +
                        "2. Запретите localhost, 127.0.0.1, 169.254.169.254, private IP\n" +
                        "3. Валидируйте URL перед использованием\n" +
                        "4. Используйте DNS rebinding защиту\n" +
                        "5. Ограничьте протоколы (только http/https)"
                    )
                    .owaspCategory("API7:2023 - Server Side Request Forgery")
                    .evidence(String.format("Параметр '%s' может быть использован для SSRF", paramName))
                    .confidence(confidence)
                    .priority(priority)
                    .impactLevel("SYSTEM_ACCESS: Доступ к внутренним системам")
                    .build());
            }
        }
        
        return vulnerabilities;
    }
    
    private boolean hasUrlValidation(Parameter param) {
        if (param.getSchema() == null) {
            return false;
        }
        
        // Проверяем есть ли format: uri или pattern
        String format = param.getSchema().getFormat();
        String pattern = param.getSchema().getPattern();
        
        return "uri".equals(format) || 
               "url".equals(format) ||
               (pattern != null && !pattern.isEmpty());
    }
}

