package com.vtb.scanner.scanners;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.heuristics.EnhancedRules;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * API10:2023 - Unsafe Consumption of APIs
 * Проверяет безопасность потребления внешних/third-party API
 */
@Slf4j
public class UnsafeConsumptionScanner implements VulnerabilityScanner {
    
    private final String targetUrl;
    
    public UnsafeConsumptionScanner(String targetUrl) {
        this.targetUrl = targetUrl;
    }
    
    @Override
    public List<Vulnerability> scan(OpenAPI openAPI, OpenAPIParser parser) {
        log.info("Запуск Unsafe Consumption Scanner (API10:2023)...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            if (pathItem.getGet() != null) {
                vulnerabilities.addAll(checkUnsafeConsumption(path, "GET", pathItem.getGet(), openAPI));
            }
            if (pathItem.getPost() != null) {
                vulnerabilities.addAll(checkUnsafeConsumption(path, "POST", pathItem.getPost(), openAPI));
            }
            if (pathItem.getPut() != null) {
                vulnerabilities.addAll(checkUnsafeConsumption(path, "PUT", pathItem.getPut(), openAPI));
            }
            if (pathItem.getDelete() != null) {
                vulnerabilities.addAll(checkUnsafeConsumption(path, "DELETE", pathItem.getDelete(), openAPI));
            }
            if (pathItem.getPatch() != null) {
                vulnerabilities.addAll(checkUnsafeConsumption(path, "PATCH", pathItem.getPatch(), openAPI));
            }
        }
        
        log.info("Unsafe Consumption Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkUnsafeConsumption(String path, String method, Operation operation, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // ИСПОЛЬЗУЕМ SmartAnalyzer для контекста!
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
            path, method, operation, openAPI);
        Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
        
        // СЕМАНТИКА: определяем тип операции
        com.vtb.scanner.semantic.OperationClassifier.OperationType opType = 
            com.vtb.scanner.semantic.OperationClassifier.classify(path, method, operation);
        
        // 1. Проверяем упоминание внешних API
        boolean consumesExternalApi = mentionsExternalApi(operation);
        
        if (consumesExternalApi) {
            boolean hasValidation = hasResponseValidation(operation);
            boolean hasTimeout = hasTimeoutMention(operation);
            
            if (!hasValidation) {
                // УМНЫЙ расчёт: SmartAnalyzer + семантика
                // Для внешних API без валидации - используем SmartAnalyzer
                Severity severity = switch(baseSeverity) {
                    case CRITICAL, HIGH -> Severity.HIGH;
                    case MEDIUM -> Severity.MEDIUM;
                    default -> Severity.MEDIUM;
                };
                
                Vulnerability tempVuln = Vulnerability.builder()
                    .type(VulnerabilityType.UNSAFE_API_CONSUMPTION)
                    .severity(severity)
                    .riskScore(riskScore)
                    .build();
                
                int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    tempVuln, operation, false, false);
                int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                    tempVuln, confidence);
                
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.UNSAFE_API_CONSUMPTION, path, method, null,
                        "Unsafe external API consumption"))
                    .type(VulnerabilityType.UNSAFE_API_CONSUMPTION)
                    .severity(severity)
                    .riskScore(riskScore)
                    .confidence(confidence)
                    .priority(priority)
                    .title("Небезопасное потребление внешних API")
                    .description(String.format(
                        "Эндпоинт %s %s использует данные от внешнего API, " +
                        "но не описывает валидацию ответов. " +
                        "Злоумышленник может контролировать внешний API и отправить вредоносные данные.",
                        method, path
                    ))
                    .endpoint(path)
                    .method(method)
                    .recommendation(
                        "При работе с внешними API:\n" +
                        "1. Валидируйте все данные от third-party\n" +
                        "2. Не доверяйте внешним данным\n" +
                        "3. Устанавливайте timeout\n" +
                        "4. Обрабатывайте ошибки\n" +
                        "5. Используйте size limits"
                    )
                    .owaspCategory("API10:2023 - Unsafe Consumption of APIs")
                    .evidence("Упоминание внешнего API без валидации")
                    .build());
            }
            
            if (!hasTimeout) {
                // Для timeout - используем SmartAnalyzer (обычно LOW, но может быть выше для критичных)
                Severity timeoutSeverity = (baseSeverity == Severity.CRITICAL || riskScore > 100) ? 
                    Severity.MEDIUM : Severity.LOW;
                
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.UNSAFE_API_CONSUMPTION, path, method, null,
                        "Timeout missing for external API"))
                    .type(VulnerabilityType.UNSAFE_API_CONSUMPTION)
                    .severity(timeoutSeverity)
                    .riskScore(riskScore)
                    .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                        Vulnerability.builder()
                            .type(VulnerabilityType.UNSAFE_API_CONSUMPTION)
                            .severity(timeoutSeverity)
                            .riskScore(riskScore)
                            .build(),
                        operation, false, false))
                    .priority(com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                        Vulnerability.builder()
                            .type(VulnerabilityType.UNSAFE_API_CONSUMPTION)
                            .severity(timeoutSeverity)
                            .build(),
                        60))
                    .title("Нет timeout для внешнего API")
                    .description(String.format(
                        "Эндпоинт %s использует внешний API без timeout. " +
                        "Медленный внешний сервис может блокировать ваш API.",
                        path
                    ))
                    .endpoint(path)
                    .method(method)
                    .recommendation(
                        "Установите разумные timeout для запросов к внешним API (например, 5-10 сек)"
                    )
                    .owaspCategory("API10:2023 - Unsafe Consumption of APIs")
                    .evidence("Нет упоминания timeout")
                    .build());
            }
        }
        
        // 2. Проверяем слишком большие ответы
        vulnerabilities.addAll(checkResponseSizeLimits(path, method, operation, riskScore, baseSeverity, openAPI));
        
        return vulnerabilities;
    }
    
    private boolean mentionsExternalApi(Operation operation) {
        String text = (operation.getDescription() != null ? operation.getDescription() : "") +
                     (operation.getSummary() != null ? operation.getSummary() : "");
        String lower = text.toLowerCase();
        
        return lower.contains("external") ||
               lower.contains("third-party") ||
               lower.contains("third party") ||
               lower.contains("webhook") ||
               lower.contains("callback") ||
               lower.contains("integration") ||
               lower.contains("proxy") ||
               lower.contains("fetch");
    }
    
    private boolean hasResponseValidation(Operation operation) {
        String text = (operation.getDescription() != null ? operation.getDescription() : "") +
                     (operation.getSummary() != null ? operation.getSummary() : "");
        String lower = text.toLowerCase();
        
        return lower.contains("validat") ||
               lower.contains("sanitiz") ||
               lower.contains("verify") ||
               lower.contains("check");
    }
    
    private boolean hasTimeoutMention(Operation operation) {
        String text = (operation.getDescription() != null ? operation.getDescription() : "") +
                     (operation.getSummary() != null ? operation.getSummary() : "");
        return text.toLowerCase().contains("timeout");
    }
    
    private List<Vulnerability> checkResponseSizeLimits(String path, String method, Operation operation, 
                                                         int riskScore, Severity baseSeverity, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (operation.getResponses() == null) {
            return vulnerabilities;
        }
        
        ApiResponse response200 = operation.getResponses().get("200");
        if (response200 != null && response200.getContent() != null) {
            Content content = response200.getContent();
            
            // Проверяем большие файлы (application/octet-stream, image/*, video/*)
            for (Map.Entry<String, MediaType> entry : content.entrySet()) {
                String contentType = entry.getKey();
                
                if (contentType.contains("octet-stream") || 
                    contentType.startsWith("image/") ||
                    contentType.startsWith("video/") ||
                    contentType.startsWith("application/pdf")) {
                    
                    MediaType mediaType = entry.getValue();
                    Schema schema = mediaType.getSchema();
                    
                    // КРИТИЧНО: Разрешаем $ref ссылки перед проверкой
                    schema = resolveSchemaRef(schema, openAPI);
                    
                    // Проверяем наличие maxLength
                    if (schema == null || schema.getMaxLength() == null) {
                        // Используем SmartAnalyzer для размера ответа
                        Severity sizeSeverity = (baseSeverity == Severity.CRITICAL || riskScore > 100) ? 
                            Severity.HIGH : Severity.MEDIUM;
                        
                        Vulnerability tempVuln = Vulnerability.builder()
                            .type(VulnerabilityType.UNSAFE_API_CONSUMPTION)
                            .severity(sizeSeverity)
                            .riskScore(riskScore)
                            .build();
                        
                        vulnerabilities.add(Vulnerability.builder()
                            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                                VulnerabilityType.UNSAFE_API_CONSUMPTION, path, method, null,
                                "Response size limit missing"))
                            .type(VulnerabilityType.UNSAFE_API_CONSUMPTION)
                            .severity(sizeSeverity)
                            .riskScore(riskScore)
                            .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                                tempVuln, operation, false, true))
                            .priority(com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                                tempVuln, 70))
                            .title("Нет ограничения размера ответа")
                            .description(String.format(
                                "Эндпоинт %s возвращает %s без ограничения размера. " +
                                "Большие файлы могут вызвать DoS.",
                                path, contentType
                            ))
                            .endpoint(path)
                            .method(method)
                            .recommendation(
                                "Установите максимальный размер для загружаемых/возвращаемых файлов. " +
                                "Используйте streaming для больших файлов."
                            )
                            .owaspCategory("API10:2023 - Unsafe Consumption of APIs")
                            .evidence("Content-Type: " + contentType + " без maxLength")
                            .build());
                    }
                }
            }
        }
        
        return vulnerabilities;
    }
    
    /**
     * Разрешить $ref ссылку на schema
     * КРИТИЧНО: Гарантирует анализ всех схем даже при ошибках resolve в библиотеке!
     */
    private Schema resolveSchemaRef(Schema schema, OpenAPI openAPI) {
        if (schema == null) {
            return null;
        }
        
        String ref = schema.get$ref();
        if (ref == null || openAPI == null || openAPI.getComponents() == null) {
            return schema;
        }
        
        // Формат: #/components/schemas/MySchema
        if (ref.startsWith("#/components/schemas/")) {
            String schemaName = ref.substring("#/components/schemas/".length());
            if (openAPI.getComponents().getSchemas() != null) {
                Schema resolved = openAPI.getComponents().getSchemas().get(schemaName);
                if (resolved != null) {
                    log.debug("Разрешена $ref ссылка в UnsafeConsumptionScanner: {} -> {}", ref, schemaName);
                    return resolved;
                }
            }
        }
        
        return schema;
    }
}

