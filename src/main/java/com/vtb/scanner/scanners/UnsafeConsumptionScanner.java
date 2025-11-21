package com.vtb.scanner.scanners;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.semantic.ContextAnalyzer;
import com.vtb.scanner.semantic.OperationClassifier;
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
        log.info("Запуск Unsafe Consumption Scanner (API10:2023) для {}...", targetUrl);
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
        if (operation == null) {
            return vulnerabilities;
        }

        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(path, method, operation, openAPI);
        Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
        OperationClassifier.OperationType opType = OperationClassifier.classify(path, method, operation);
        ContextAnalyzer.APIContext apiContext = openAPI != null ? ContextAnalyzer.detectContext(openAPI) : ContextAnalyzer.APIContext.GENERAL;
        boolean telecomContext = apiContext == ContextAnalyzer.APIContext.TELECOM;
        boolean automotiveContext = apiContext == ContextAnalyzer.APIContext.AUTOMOTIVE;

        String operationText = extractOperationText(operation);
        boolean consumesExternalApi = mentionsExternalApi(operationText);
        boolean isWebhook = mentionsWebhook(operationText);
        boolean hasSignature = hasSignatureEvidence(operationText);
        boolean hasValidation = hasResponseValidation(operationText);
        boolean hasTimeout = hasTimeoutMention(operationText);
        boolean hasRetry = hasRetryMention(operationText);
        boolean hasResilience = hasResilienceMention(operationText);
        boolean referencesSensitiveProvider = mentionsSensitiveProvider(operationText);

        if (consumesExternalApi) {
            Severity severity = determineExternalSeverity(baseSeverity, apiContext, opType, hasValidation, hasSignature, referencesSensitiveProvider);

            if (!hasValidation) {
                Vulnerability temp = Vulnerability.builder()
                    .type(VulnerabilityType.UNSAFE_API_CONSUMPTION)
                    .severity(severity)
                    .riskScore(riskScore)
                    .build();
                int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(temp, operation, false, false);
                int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(temp, confidence);

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
                    .description(buildExternalDescription(method, path, opType, apiContext, hasValidation, hasSignature))
                    .endpoint(path)
                    .method(method)
                    .recommendation(buildExternalRecommendations(apiContext))
                    .owaspCategory("API10:2023 - Unsafe Consumption of APIs")
                    .impactLevel(resolveExternalImpact(apiContext, opType))
                    .evidence("Упоминание внешнего API без валидации")
                    .build());
            }

            if (isWebhook && !hasSignature) {
                Severity webhookSeverity = telecomContext || automotiveContext ? Severity.CRITICAL : Severity.HIGH;
                Vulnerability temp = Vulnerability.builder()
                    .type(VulnerabilityType.UNSAFE_API_CONSUMPTION)
                    .severity(webhookSeverity)
                    .riskScore(riskScore)
                    .build();
                int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(temp, operation, false, false);
                int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(temp, confidence);

                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.UNSAFE_API_CONSUMPTION, path, method, null,
                        "Webhook without signature"))
                    .type(VulnerabilityType.UNSAFE_API_CONSUMPTION)
                    .severity(webhookSeverity)
                    .riskScore(riskScore)
                    .confidence(confidence)
                    .priority(priority)
                    .title("Внешний webhook без подписи/секрета")
                    .description(String.format(
                        "Эндпоинт %s %s принимает webhook/коллбек, но в спецификации отсутствуют признаки подписи, HMAC или секрета.\n" +
                        "Это позволяет атакующему подделать отклик внешнего сервиса.",
                        method, path))
                    .endpoint(path)
                    .method(method)
                    .recommendation("Для всех webhook/API callback используйте HMAC подпись (X-Signature), секреты, mutual TLS или allowlist IP.")
                    .owaspCategory("API10:2023 - Unsafe Consumption of APIs")
                    .impactLevel("INTEGRITY_ATTACK: Подделка webhook")
                    .evidence("Webhook обнаружен, но нет signature/hmac указаний")
                    .build());
            }

            if (!hasTimeout) {
                Severity timeoutSeverity = telecomContext || automotiveContext ? Severity.MEDIUM : (baseSeverity == Severity.CRITICAL || riskScore > 100 ? Severity.MEDIUM : Severity.LOW);
                Vulnerability temp = Vulnerability.builder()
                    .type(VulnerabilityType.UNSAFE_API_CONSUMPTION)
                    .severity(timeoutSeverity)
                    .riskScore(riskScore)
                    .build();
                int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(temp, operation, false, false);
                int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(temp, confidence);

                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.UNSAFE_API_CONSUMPTION, path, method, null,
                        "Timeout missing for external API"))
                    .type(VulnerabilityType.UNSAFE_API_CONSUMPTION)
                    .severity(timeoutSeverity)
                    .riskScore(riskScore)
                    .confidence(confidence)
                    .priority(priority)
                    .title("Нет timeout для внешнего API")
                    .description(String.format("Эндпоинт %s использует внешний API без описания timeout. Медленный сервис может блокировать ваш API.", path))
                    .endpoint(path)
                    .method(method)
                    .recommendation("Задайте таймауты (5-10 сек), ограничение на количество повторов и fallback при сбоях внешних API.")
                    .owaspCategory("API10:2023 - Unsafe Consumption of APIs")
                    .impactLevel(resolveTimeoutImpact(apiContext))
                    .evidence("Нет упоминания timeout при работе с внешним API")
                    .build());
            }

            if (!hasRetry && !hasResilience) {
                Severity resilienceSeverity = telecomContext || automotiveContext ? Severity.HIGH : Severity.MEDIUM;
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.UNSAFE_API_CONSUMPTION, path, method, null,
                        "No resilience policies for external API"))
                    .type(VulnerabilityType.UNSAFE_API_CONSUMPTION)
                    .severity(resilienceSeverity)
                    .riskScore(riskScore)
                    .title("Отсутствуют retry/circuit breaker для внешнего API")
                    .description(String.format(
                        "Эндпоинт %s %s использует внешний сервис, но не описывает retry, circuit breaker или fallback.",
                        method, path))
                    .endpoint(path)
                    .method(method)
                    .recommendation("Опишите retry/backoff, circuit breaker и fallback логику при отказах внешнего сервиса.")
                    .owaspCategory("API10:2023 - Unsafe Consumption of APIs")
                    .impactLevel("AVAILABILITY_RISK: Зависимость от нестабильного провайдера")
                    .confidence(60)
                    .priority(com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                        Vulnerability.builder().type(VulnerabilityType.UNSAFE_API_CONSUMPTION).severity(resilienceSeverity).build(), 60))
                    .build());
            }
        }

        vulnerabilities.addAll(checkResponseSizeLimits(path, method, operation, riskScore, baseSeverity, openAPI));
        
        return vulnerabilities;
    }

    private String extractOperationText(Operation operation) {
        StringBuilder sb = new StringBuilder();
        if (operation != null) {
            if (operation.getSummary() != null) {
                sb.append(operation.getSummary().toLowerCase(Locale.ROOT)).append(' ');
            }
            if (operation.getDescription() != null) {
                sb.append(operation.getDescription().toLowerCase(Locale.ROOT)).append(' ');
            }
        }
        return sb.toString();
    }

    private Severity determineExternalSeverity(Severity baseSeverity,
                                               ContextAnalyzer.APIContext context,
                                               OperationClassifier.OperationType opType,
                                               boolean hasValidation,
                                               boolean hasSignature,
                                               boolean referencesSensitiveProvider) {
        Severity severity = switch (baseSeverity) {
            case CRITICAL, HIGH -> Severity.HIGH;
            case MEDIUM -> Severity.MEDIUM;
            default -> Severity.MEDIUM;
        };

        if (opType == OperationClassifier.OperationType.ADMIN_ACTION || referencesSensitiveProvider) {
            severity = Severity.HIGH;
        }
        if (context == ContextAnalyzer.APIContext.BANKING ||
            context == ContextAnalyzer.APIContext.TELECOM ||
            context == ContextAnalyzer.APIContext.AUTOMOTIVE) {
            severity = Severity.HIGH;
        }
        if (hasValidation && hasSignature) {
            severity = severity.compareTo(Severity.MEDIUM) > 0 ? Severity.MEDIUM : severity;
        }
        return severity;
    }

    private String buildExternalDescription(String method,
                                            String path,
                                            OperationClassifier.OperationType opType,
                                            ContextAnalyzer.APIContext context,
                                            boolean hasValidation,
                                            boolean hasSignature) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Эндпоинт %s %s обращается к внешнему API (тип операции: %s). ", method, path, opType));
        if (!hasValidation) {
            sb.append("Валидация данных не описана. ");
        } else {
            sb.append("Валидация упомянута, но убедитесь, что она строгая. ");
        }
        if (!hasSignature) {
            sb.append("В спецификации нет признаков подписи/секрета. ");
        }
        if (context == ContextAnalyzer.APIContext.BANKING) {
            sb.append("Для банковских интеграций критично контролировать источник и формат ответов. ");
        } else if (context == ContextAnalyzer.APIContext.TELECOM) {
            sb.append("Для телеком сервисов отсутствие валидации может привести к взлому биллинга/roaming. ");
        } else if (context == ContextAnalyzer.APIContext.AUTOMOTIVE) {
            sb.append("В connected car сценариях это угрожает безопасности транспорта. ");
        }
        return sb.toString().trim();
    }

    private String buildExternalRecommendations(ContextAnalyzer.APIContext context) {
        StringBuilder sb = new StringBuilder();
        sb.append("1. Проверяйте схему и тип данных, возвращаемых внешним API.\n");
        sb.append("2. Используйте allowlist доменов/сертификатов и mutual TLS там, где возможно.\n");
        sb.append("3. Логируйте и мониторьте ответы третьих сторон.\n");
        sb.append("4. Добавьте retry/backoff, circuit breaker и таймауты.\n");
        if (context == ContextAnalyzer.APIContext.BANKING) {
            sb.append("5. Для финансовых интеграций используйте подпись сообщений и двухсторонний TLS.\n");
        } else if (context == ContextAnalyzer.APIContext.TELECOM) {
            sb.append("5. Для телеком-интеграций проверяйте msisdn/сим данные и используйте audit trail.\n");
        } else if (context == ContextAnalyzer.APIContext.AUTOMOTIVE) {
            sb.append("5. Для connected car сервисов требуйте сертификаты/подписи OTA-команд.\n");
        }
        sb.append("6. Ограничьте размер ответов и фильтруйте непредвиденные поля.");
        return sb.toString();
    }

    private String resolveExternalImpact(ContextAnalyzer.APIContext context,
                                          OperationClassifier.OperationType opType) {
        if (context == ContextAnalyzer.APIContext.BANKING) {
            return "FINANCIAL_FRAUD: Компрометация внешнего провайдера";
        }
        if (context == ContextAnalyzer.APIContext.TELECOM) {
            return "TELECOM_OUTAGE: Неконтролируемые ответы внешнего оператора";
        }
        if (context == ContextAnalyzer.APIContext.AUTOMOTIVE) {
            return "CONNECTED_CAR: Вредоносные команды телематике";
        }
        if (opType == OperationClassifier.OperationType.ADMIN_ACTION) {
            return "PRIVILEGE_ESCALATION: Админ действия через внешнее API";
        }
        return "INTEGRITY_RISK: Небезопасный внешней источник";
    }

    private String resolveTimeoutImpact(ContextAnalyzer.APIContext context) {
        if (context == ContextAnalyzer.APIContext.BANKING || context == ContextAnalyzer.APIContext.TELECOM) {
            return "SERVICE_OUTAGE: Зависимость от внешнего провайдера";
        }
        if (context == ContextAnalyzer.APIContext.AUTOMOTIVE) {
            return "SAFETY_RISK: Подвисшие команды connected car";
        }
        return "AVAILABILITY_RISK: Потенциальное блокирование потоков";
    }
    
    private boolean mentionsExternalApi(String operationText) {
        return EXTERNAL_API_KEYWORDS.stream().anyMatch(operationText::contains);
    }

    private boolean mentionsWebhook(String operationText) {
        return WEBHOOK_KEYWORDS.stream().anyMatch(operationText::contains);
    }

    private boolean hasSignatureEvidence(String operationText) {
        return SIGNATURE_KEYWORDS.stream().anyMatch(operationText::contains);
    }

    private boolean hasResponseValidation(String operationText) {
        return VALIDATION_KEYWORDS.stream().anyMatch(operationText::contains);
    }

    private boolean hasTimeoutMention(String operationText) {
        return TIMEOUT_KEYWORDS.stream().anyMatch(operationText::contains);
    }

    private boolean hasRetryMention(String operationText) {
        return RETRY_KEYWORDS.stream().anyMatch(operationText::contains);
    }

    private boolean hasResilienceMention(String operationText) {
        return RESILIENCE_KEYWORDS.stream().anyMatch(operationText::contains);
    }

    private boolean mentionsSensitiveProvider(String operationText) {
        return SENSITIVE_PROVIDER_KEYWORDS.stream().anyMatch(operationText::contains);
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
                    Schema<?> schema = mediaType.getSchema();
                    
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

    private static final Set<String> EXTERNAL_API_KEYWORDS = Set.of(
        "external", "third-party", "third party", "integration", "partner api", "supplier api", "proxy", "fetch", "adapter", "msisdn provider"
    );
    private static final Set<String> WEBHOOK_KEYWORDS = Set.of(
        "webhook", "callback", "notification url", "notify url", "push url", "event handler"
    );
    private static final Set<String> SIGNATURE_KEYWORDS = Set.of(
        "signature", "hmac", "secret", "x-signature", "signing", "jwt", "token", "verify signature"
    );
    private static final Set<String> VALIDATION_KEYWORDS = Set.of(
        "validate", "validation", "sanitize", "sanitiz", "verify", "schema", "json schema", "check"
    );
    private static final Set<String> TIMEOUT_KEYWORDS = Set.of(
        "timeout", "time out", "sla", "latency", "request timeout", "socket timeout"
    );
    private static final Set<String> RETRY_KEYWORDS = Set.of(
        "retry", "retries", "backoff", "retry-after", "repeat", "повтор", "exponential backoff"
    );
    private static final Set<String> RESILIENCE_KEYWORDS = Set.of(
        "circuit breaker", "breaker", "bulkhead", "fallback", "graceful degrade", "resilience", "failover"
    );
    private static final Set<String> SENSITIVE_PROVIDER_KEYWORDS = Set.of(
        "aml", "compliance provider", "credit bureau", "roaming", "sim swap", "payment gateway", "telematics hub"
    );

    /**
     * Разрешить $ref ссылку на schema
     * КРИТИЧНО: Гарантирует анализ всех схем даже при ошибках resolve в библиотеке!
     */
    private Schema<?> resolveSchemaRef(Schema<?> schema, OpenAPI openAPI) {
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
                Schema<?> resolved = openAPI.getComponents().getSchemas().get(schemaName);
                if (resolved != null) {
                    log.debug("Разрешена $ref ссылка в UnsafeConsumptionScanner: {} -> {}", ref, schemaName);
                    return resolved;
                }
            }
        }
        
        return schema;
    }
}


