package com.vtb.scanner.scanners;

import com.vtb.scanner.config.ScannerConfig;
import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.deep.DeepSchemaAnalyzer;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.semantic.ContextAnalyzer;
import com.vtb.scanner.util.AccessControlHeuristics;
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
 * API3:2023 - Broken Object Property Level Authorization
 * Проверяет чрезмерное раскрытие данных в ответах (Excessive Data Exposure)
 */
@Slf4j
public class PropertyAuthScanner implements VulnerabilityScanner {
    
    @SuppressWarnings("unused")
    private final String targetUrl;
    private final ScannerConfig config;
    private final Set<String> sensitiveFields;
    private final Set<String> readonlyFields;
    
    public PropertyAuthScanner(String targetUrl) {
        this.targetUrl = targetUrl;
        
        // Загружаем из конфига (убираем хардкод!)
        this.config = ScannerConfig.load();
        this.sensitiveFields = new HashSet<>(config.getSensitiveResponseFields());
        this.readonlyFields = new HashSet<>(config.getReadonlyFields());
    }
    
    @Override
    public List<Vulnerability> scan(OpenAPI openAPI, OpenAPIParser parser) {
        log.info("Запуск Property Authorization Scanner (API3:2023)...");
        log.info("Включен глубокий анализ вложенных объектов (до 10 уровней).");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // Проверяем GET (чрезмерное раскрытие) + ГЛУБОКИЙ анализ
            if (pathItem.getGet() != null) {
                vulnerabilities.addAll(checkExcessiveDataExposure(path, "GET", pathItem.getGet(), openAPI));
                vulnerabilities.addAll(deepCheckResponse(path, "GET", pathItem.getGet(), openAPI));
            }
            
            // Проверяем PUT/PATCH (Mass Assignment) + ГЛУБОКИЙ анализ
            if (pathItem.getPut() != null) {
                vulnerabilities.addAll(checkMassAssignment(path, "PUT", pathItem.getPut(), openAPI));
                vulnerabilities.addAll(deepCheckRequestBody(path, "PUT", pathItem.getPut(), openAPI));
            }
            if (pathItem.getPatch() != null) {
                vulnerabilities.addAll(checkMassAssignment(path, "PATCH", pathItem.getPatch(), openAPI));
                vulnerabilities.addAll(deepCheckRequestBody(path, "PATCH", pathItem.getPatch(), openAPI));
            }
            
            // Проверяем POST + ГЛУБОКИЙ анализ
            if (pathItem.getPost() != null) {
                vulnerabilities.addAll(checkMassAssignment(path, "POST", pathItem.getPost(), openAPI));
                vulnerabilities.addAll(deepCheckRequestBody(path, "POST", pathItem.getPost(), openAPI));
            }
        }
        
        log.info("Property Authorization Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    /**
     * ГЛУБОКАЯ проверка request body (рекурсивно!)
     */
    private List<Vulnerability> deepCheckRequestBody(String path, String method, Operation operation, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (operation.getRequestBody() == null) return vulnerabilities;
        
        Content content = operation.getRequestBody().getContent();
        if (content == null) return vulnerabilities;
        
        MediaType jsonType = content.get("application/json");
        if (jsonType != null && jsonType.getSchema() != null) {
            // КРИТИЧНО: Передаем openAPI для разрешения $ref ссылок
            List<DeepSchemaAnalyzer.SchemaIssue> issues = 
                DeepSchemaAnalyzer.analyzeRequestBody(jsonType.getSchema(), path, method, openAPI);
            
            for (DeepSchemaAnalyzer.SchemaIssue issue : issues) {
                // ДИНАМИЧЕСКИЙ расчет confidence!
                Vulnerability tempVuln = Vulnerability.builder()
                    .type(VulnerabilityType.BROKEN_OBJECT_PROPERTY)
                    .severity(issue.getSeverity())
                    .build();
                
                int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    tempVuln, operation, false, true); // hasEvidence=true (нашли в глубине!)
                
                int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                    tempVuln, confidence);
                
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.BROKEN_OBJECT_PROPERTY, path, method, issue.getPath(),
                        "Deep request body issue"))
                    .type(VulnerabilityType.BROKEN_OBJECT_PROPERTY)
                    .severity(issue.getSeverity())
                    .title("Проблема в поле: " + issue.getPath())
                    .description(issue.getDescription())
                    .endpoint(path)
                    .method(method)
                    .recommendation("Используйте DTO с whitelist полей")
                    .owaspCategory("API3:2023 - Property Auth (Deep)")
                    .evidence("Найдено на глубине: " + issue.getPath())
                    .confidence(confidence)
                    .priority(priority)
                    .impactLevel("DATA_EXPOSURE: Чувствительные данные")
                    .build());
            }
        }
        
        return vulnerabilities;
    }
    
    /**
     * ГЛУБОКАЯ проверка response (рекурсивно!)
     * ИСПОЛЬЗУЕТ EnhancedRules для поиска чувствительных полей!
     */
    private List<Vulnerability> deepCheckResponse(String path, String method, Operation operation, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (operation.getResponses() == null) return vulnerabilities;
        
        ApiResponse response200 = operation.getResponses().get("200");
        if (response200 == null || response200.getContent() == null) return vulnerabilities;
        
        MediaType jsonType = response200.getContent().get("application/json");
        if (jsonType != null && jsonType.getSchema() != null) {
            // 1. Deep analyzer (рекурсивно)
            // КРИТИЧНО: Передаем openAPI для разрешения $ref ссылок
            List<DeepSchemaAnalyzer.SchemaIssue> issues =
                DeepSchemaAnalyzer.analyzeResponse(jsonType.getSchema(), path, method, openAPI);

            Set<String> reportedPaths = new HashSet<>();
            for (DeepSchemaAnalyzer.SchemaIssue issue : issues) {
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.EXCESSIVE_DATA_EXPOSURE, path, method, issue.getPath(),
                        "Deep response body issue"))
                    .type(VulnerabilityType.EXCESSIVE_DATA_EXPOSURE)
                    .severity(issue.getSeverity())
                    .title("Чувствительные данные в поле: " + issue.getPath())
                    .description(issue.getDescription())
                    .endpoint(path)
                    .method(method)
                    .recommendation("Фильтруйте чувствительные поля из ответа")
                    .owaspCategory("API3:2023 - Excessive Data (Deep)")
                    .evidence("Найдено на глубине: " + issue.getPath())
                    .build());
                reportedPaths.add(issue.getPath());
            }
            
            // 2. ИСПОЛЬЗУЕМ EnhancedRules для чувствительных полей!
            // КРИТИЧНО: Разрешаем $ref ссылки перед анализом
            Schema<?> resolvedSchema = resolveSchemaRef(jsonType.getSchema(), openAPI);
            List<String> sensitiveFields = com.vtb.scanner.heuristics.EnhancedRules.findSensitiveFieldsInResponse(
                resolvedSchema);
            
            for (String field : sensitiveFields) {
                if (reportedPaths.contains(field)) {
                    continue;
                }
                Vulnerability tempVuln = Vulnerability.builder()
                    .type(VulnerabilityType.EXCESSIVE_DATA_EXPOSURE)
                    .severity(Severity.HIGH)
                    .build();
                
                int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    tempVuln, operation, false, true);
                
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.EXCESSIVE_DATA_EXPOSURE, path, method, field,
                        "Sensitive field in response"))
                    .type(VulnerabilityType.EXCESSIVE_DATA_EXPOSURE)
                    .severity(Severity.HIGH)
                    .title("Чувствительное поле в ответе: " + field)
                    .description(String.format(
                        "Поле '%s' в ответе содержит чувствительные данные (password, token, secret).\n" +
                        "Такие поля НЕ должны передаваться клиенту!",
                        field))
                    .endpoint(path)
                    .method(method)
                    .recommendation("Исключите поле '" + field + "' из ответа или замените на '***'")
                    .owaspCategory("API3:2023 - Excessive Data Exposure")
                    .evidence("Найдено чувствительное поле: " + field)
                    .confidence(confidence)
                    .priority(com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(tempVuln, confidence))
                    .build());
            }
            
            // 3. ИСПОЛЬЗУЕМ EnhancedRules для персональных данных (ФЗ-152)!
            // КРИТИЧНО: Разрешаем $ref ссылки перед анализом
            Schema<?> resolvedSchemaForPersonal = resolveSchemaRef(jsonType.getSchema(), openAPI);
            if (com.vtb.scanner.heuristics.EnhancedRules.hasPersonalData(resolvedSchemaForPersonal)) {
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.EXCESSIVE_DATA_EXPOSURE, path, method, null,
                        "Personal data in response (FZ-152)"))
                    .type(VulnerabilityType.EXCESSIVE_DATA_EXPOSURE)
                    .severity(Severity.HIGH)
                    .title("Персональные данные в ответе (ФЗ-152)")
                    .description(String.format(
                        "Эндпоинт %s возвращает персональные данные (ФИО, паспорт, ИНН, адрес).\n" +
                        "Требуется защита в соответствии с ФЗ-152!",
                        path))
                    .endpoint(path)
                    .method(method)
                    .recommendation(
                        "1. Проверьте авторизацию на доступ к ПД\n" +
                        "2. Логируйте все обращения к ПД\n" +
                        "3. Шифруйте передачу (TLS 1.2+)\n" +
                        "4. Обезличьте где возможно")
                    .owaspCategory("API3:2023 - Excessive Data + ФЗ-152")
                    .evidence("Обнаружены поля с персональными данными")
                    .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                        Vulnerability.builder()
                            .type(VulnerabilityType.EXCESSIVE_DATA_EXPOSURE)
                            .severity(Severity.HIGH)
                            .build(),
                        operation, false, true))
                    .priority(1)
                    .impactLevel("LEGAL_COMPLIANCE: Нарушение ФЗ-152")
                    .build());
            }
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка чрезмерного раскрытия данных в ответах
     * 
     * С СЕМАНТИКОЙ: для READ операций проверяем строже!
     */
    private List<Vulnerability> checkExcessiveDataExposure(String path, String method, Operation operation, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // ИСПОЛЬЗУЕМ SmartAnalyzer для контекста!
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
            path, method, operation, openAPI);
        Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
        
        // СЕМАНТИКА
        com.vtb.scanner.semantic.OperationClassifier.OperationType opType = 
            com.vtb.scanner.semantic.OperationClassifier.classify(path, method, operation);
        
        if (operation.getResponses() == null) {
            return vulnerabilities;
        }
        
        // Проверяем успешные ответы (200, 201)
        for (String code : Arrays.asList("200", "201")) {
            ApiResponse response = operation.getResponses().get(code);
            if (response == null || response.getContent() == null) continue;
            
            Content content = response.getContent();
            MediaType mediaType = content.get("application/json");
            if (mediaType == null || mediaType.getSchema() == null) continue;
            
            Schema<?> schema = mediaType.getSchema();
            // КРИТИЧНО: Разрешаем $ref ссылки для полного анализа
            schema = resolveSchemaRef(schema, openAPI);
            Set<String> foundSensitive = findSensitiveFields(schema);
            
            if (!foundSensitive.isEmpty()) {
                // Используем SmartAnalyzer для excessive data exposure
                Severity severity = switch(baseSeverity) {
                    case CRITICAL, HIGH -> Severity.HIGH;
                    case MEDIUM -> Severity.HIGH;
                    default -> Severity.MEDIUM;
                };
                if (opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.READ &&
                    severity.compareTo(Severity.HIGH) < 0) {
                    severity = Severity.HIGH;
                }
                
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.EXCESSIVE_DATA_EXPOSURE, path, method, null,
                        "Excessive data exposure"))
                    .type(VulnerabilityType.EXCESSIVE_DATA_EXPOSURE)
                    .severity(severity)
                    .riskScore(riskScore)
                    .title("Чрезмерное раскрытие данных в ответе")
                    .description(String.format(
                        "Эндпоинт %s возвращает чувствительные поля: %s. " +
                        "Клиент получает больше данных, чем нужно.",
                        path, String.join(", ", foundSensitive)
                    ))
                    .endpoint(path)
                    .method(method)
                    .recommendation(
                        "Используйте DTO/View модели для фильтрации ответов. " +
                        "Возвращайте только необходимые поля. " +
                        "Никогда не возвращайте пароли, токены, секреты."
                    )
                    .owaspCategory("API3:2023 - Broken Object Property Level Authorization")
                    .evidence("Обнаружены чувствительные поля: " + foundSensitive)
                    .build());
            }
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка Mass Assignment уязвимостей (УЛУЧШЕННАЯ с EnhancedRules + семантикой + SmartAnalyzer!)
     */
    private List<Vulnerability> checkMassAssignment(String path, String method, Operation operation, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // ИСПОЛЬЗУЕМ SmartAnalyzer для контекста!
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
            path, method, operation, openAPI);
        Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
        
        if (operation.getRequestBody() == null || 
            operation.getRequestBody().getContent() == null) {
            return vulnerabilities;
        }
        
        Content content = operation.getRequestBody().getContent();
        MediaType mediaType = content.get("application/json");
        if (mediaType == null || mediaType.getSchema() == null) {
            return vulnerabilities;
        }
        
        Schema<?> schema = mediaType.getSchema();
        // КРИТИЧНО: Разрешаем $ref ссылки для полного анализа
        schema = resolveSchemaRef(schema, openAPI);
        Map<String, Schema<?>> schemaProperties = collectSchemaProperties(schema, new IdentityHashMap<>());

        // СЕМАНТИКА: определяем тип операции
        com.vtb.scanner.semantic.OperationClassifier.OperationType opType = 
            com.vtb.scanner.semantic.OperationClassifier.classify(path, method, operation);

        boolean hasStrongAuthorization = AccessControlHeuristics.hasStrongAuthorization(operation, openAPI);
        boolean hasExplicitAccess = AccessControlHeuristics.hasExplicitAccessControl(operation, path, openAPI);
        boolean hasConsentEvidence = AccessControlHeuristics.hasConsentEvidence(operation, openAPI);
        boolean isOpenBankingOperation = AccessControlHeuristics.isOpenBankingOperation(path, operation, openAPI);
        ContextAnalyzer.APIContext apiContext = ContextAnalyzer.detectContext(openAPI);

        // 1. Read-only поля (старая логика)
        Set<String> foundReadonly = findReadonlyFields(schema);
        foundReadonly = filterReadonlyFalsePositives(foundReadonly, path, operation);
        
        if (!foundReadonly.isEmpty()) {
            // Используем SmartAnalyzer для read-only полей
            Severity severity = switch(baseSeverity) {
                case CRITICAL, HIGH -> Severity.HIGH;
                case MEDIUM -> Severity.MEDIUM;
                default -> Severity.MEDIUM;
            };
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BROKEN_OBJECT_PROPERTY, path, method, null,
                    "Read-only fields in request"))
                .type(VulnerabilityType.BROKEN_OBJECT_PROPERTY)
                .severity(severity)
                .riskScore(riskScore)
                .title("Read-only поля в request")
                .description(String.format(
                    "Request body позволяет изменять read-only поля: %s. " +
                    "Злоумышленник может изменить id, timestamps, статусы.",
                    String.join(", ", foundReadonly)
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Используйте whitelist разрешенных полей для изменения. " +
                    "Read-only поля (id, timestamps) не должны приниматься в input. " +
                    "Валидируйте и отклоняйте запросы с неожиданными полями."
                )
                .owaspCategory("API6:2023 - Mass Assignment (Read-only)")
                .evidence("Обнаружены read-only поля в request: " + foundReadonly)
                .build());
        }
        
        // 2. Опасные поля через EnhancedRules (role, admin, balance, permissions и т.д.)
        List<String> dangerousFields = com.vtb.scanner.heuristics.EnhancedRules
            .findMassAssignmentRiskFields(schema, operation, path);
        dangerousFields = filterMassAssignmentBusinessContext(dangerousFields, schemaProperties,
            hasStrongAuthorization, hasExplicitAccess, hasConsentEvidence, isOpenBankingOperation, apiContext);

        if (!dangerousFields.isEmpty()) {
            Severity severity = calculateMassAssignmentSeverity(baseSeverity, opType, riskScore, dangerousFields,
                hasStrongAuthorization, hasExplicitAccess, hasConsentEvidence, isOpenBankingOperation, apiContext);
            int adjustedRiskScore = adjustMassAssignmentRiskScore(riskScore, baseSeverity, severity,
                hasStrongAuthorization, hasExplicitAccess, hasConsentEvidence, isOpenBankingOperation, apiContext);

            Vulnerability tempVuln = Vulnerability.builder()
                .type(VulnerabilityType.BROKEN_OBJECT_PROPERTY)
                .severity(severity)
                .riskScore(adjustedRiskScore)
                .build();

            int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                tempVuln, operation, false, true);
            int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(tempVuln, confidence);

            String impactLevel = determineMassAssignmentImpact(dangerousFields, severity);
            String evidence = buildMassAssignmentEvidence(dangerousFields, hasStrongAuthorization,
                hasExplicitAccess, hasConsentEvidence, isOpenBankingOperation, adjustedRiskScore, riskScore);

            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BROKEN_OBJECT_PROPERTY, path, method, null,
                    "Mass assignment risk"))
                .type(VulnerabilityType.BROKEN_OBJECT_PROPERTY)
                .severity(severity)
                .riskScore(adjustedRiskScore)
                .title("Поля требуют whitelist (Mass Assignment риск)")
                .description(String.format(
                    "Request body содержит бизнес-критичные поля: %s. " +
                    "Проверьте, что сервер применяет whitelist и дополнительные проверки (лимиты, согласия, роли).",
                    String.join(", ", dangerousFields)
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Mass Assignment защита:\n\n" +
                    "1. Используйте DTO/Whitelist разрешенных полей\n" +
                    "2. Игнорируйте неожиданные параметры (Bean Validation)\n" +
                    "3. Для токен/consent полей фиксируйте значения на сервере\n" +
                    "4. Для финансовых полей (amount, balance) проверяйте лимиты и владельца счёта\n" +
                    "5. Логируйте изменения ролей/разрешений"
                )
                .owaspCategory("API6:2023 - Mass Assignment")
                .evidence(evidence)
                .confidence(confidence)
                .priority(priority)
                .impactLevel(impactLevel)
                .build());
        }
        
        return vulnerabilities;
    }
    
    /**
     * Рекурсивный поиск чувствительных полей в схеме
     */
    private Set<String> findSensitiveFields(Schema<?> schema) {
        Set<String> found = new LinkedHashSet<>();
        collectSchemaProperties(schema, new IdentityHashMap<>()).forEach((fieldPath, propertySchema) -> {
            String lowerName = fieldPath.toLowerCase(Locale.ROOT);
            for (String sensitive : sensitiveFields) {
                if (lowerName.contains(sensitive.toLowerCase(Locale.ROOT))) {
                    found.add(fieldPath);
                    break;
                }
            }
            if (propertySchema != null) {
                List<String> enhanced = com.vtb.scanner.heuristics.EnhancedRules.findSensitiveFieldsInResponse(propertySchema);
                for (String enhancedField : enhanced) {
                    found.add(fieldPath + "." + enhancedField);
                }
            }
        });
        return found;
    }
    
    /**
     * Поиск read-only полей в схеме
     */
    private Set<String> findReadonlyFields(Schema<?> schema) {
        Set<String> found = new LinkedHashSet<>();
        collectSchemaProperties(schema, new IdentityHashMap<>()).forEach((fieldPath, fieldSchema) -> {
            if (fieldSchema != null && Boolean.TRUE.equals(fieldSchema.getReadOnly())) {
                found.add(fieldPath);
                return;
            }
            String lowerName = fieldPath.toLowerCase(Locale.ROOT);
            for (String readonly : readonlyFields) {
                if (lowerName.endsWith(readonly.toLowerCase(Locale.ROOT))) {
                    found.add(fieldPath);
                    break;
                }
            }
        });
        return found;
    }

    private Set<String> filterReadonlyFalsePositives(Set<String> fields, String path, Operation operation) {
        if (fields == null || fields.isEmpty()) {
            return fields;
        }
        String lowerPath = path != null ? path.toLowerCase(Locale.ROOT) : "";
        String text = "";
        if (operation != null) {
            StringBuilder builder = new StringBuilder();
            if (operation.getSummary() != null) {
                builder.append(operation.getSummary()).append(' ');
            }
            if (operation.getDescription() != null) {
                builder.append(operation.getDescription());
            }
            text = builder.toString().toLowerCase(Locale.ROOT);
        }

        Set<String> filtered = new HashSet<>();
        for (String field : fields) {
            if (field == null) {
                continue;
            }
            String normalizedField = field.replace("[]", "");
            String lastSegment = normalizedField.contains(".")
                ? normalizedField.substring(normalizedField.lastIndexOf('.') + 1)
                : normalizedField;
            String lowerField = lastSegment.toLowerCase(Locale.ROOT);
            if (isLegitimateReadonlyField(lowerField, lowerPath, text)) {
                continue;
            }
            filtered.add(field);
        }
        return filtered;
    }

    private boolean isLegitimateReadonlyField(String lowerField, String lowerPath, String text) {
        if ("status".equals(lowerField) && (lowerPath.endsWith("/status") || text.contains("status"))) {
            return true;
        }
        if ("permissions".equals(lowerField) || lowerField.contains("consent")) {
            return lowerPath.contains("consent") || text.contains("consent");
        }
        if ("client_id".equals(lowerField)) {
            return lowerPath.contains("consent") || lowerPath.contains("bank-token") || text.contains("open banking");
        }
        if (lowerField.endsWith("_id")) {
            if (lowerField.contains("account") && lowerPath.contains("account")) {
                return true;
            }
            if (lowerField.contains("product") && lowerPath.contains("product")) {
                return true;
            }
        }
        if ("destination_account_id".equals(lowerField) || "source_account_id".equals(lowerField)) {
            return lowerPath.contains("payment") || lowerPath.contains("accounts");
        }
        return false;
    }
    
    private Map<String, Schema<?>> collectSchemaProperties(Schema<?> schema,
                                                           IdentityHashMap<Schema<?>, Boolean> visited) {
        Map<String, Schema<?>> properties = new LinkedHashMap<>();
        collectSchemaPropertiesRecursive(schema, "", visited, properties);
        return properties;
    }
    
    private void collectSchemaPropertiesRecursive(Schema<?> schema,
                                                  String prefix,
                                                  IdentityHashMap<Schema<?>, Boolean> visited,
                                                  Map<String, Schema<?>> target) {
        if (schema == null) {
            return;
        }
        if (visited.put(schema, Boolean.TRUE) != null) {
            return;
        }
        try {
            if (schema.getProperties() != null) {
                schema.getProperties().forEach((key, value) -> {
                    if (key == null || !(value instanceof Schema)) {
                        return;
                    }
                    String fieldPath = prefix.isEmpty() ? key : prefix + "." + key;
                    Schema<?> propertySchema = (Schema<?>) value;
                    target.put(fieldPath, propertySchema);
                    if (isObjectLike(propertySchema)) {
                        collectSchemaPropertiesRecursive(propertySchema, fieldPath, visited, target);
                    }
                    if ("array".equalsIgnoreCase(propertySchema.getType()) && propertySchema.getItems() != null) {
                        collectSchemaPropertiesRecursive(propertySchema.getItems(), fieldPath + "[]", visited, target);
                    }
                });
            }
            if (schema.getAllOf() != null) {
                for (Schema<?> fragment : schema.getAllOf()) {
                    collectSchemaPropertiesRecursive(fragment, prefix, visited, target);
                }
            }
            if (schema.getAnyOf() != null) {
                for (Schema<?> fragment : schema.getAnyOf()) {
                    collectSchemaPropertiesRecursive(fragment, prefix, visited, target);
                }
            }
            if (schema.getOneOf() != null) {
                for (Schema<?> fragment : schema.getOneOf()) {
                    collectSchemaPropertiesRecursive(fragment, prefix, visited, target);
                }
            }
        } finally {
            visited.remove(schema);
        }
    }
    
    private boolean isObjectLike(Schema<?> schema) {
        if (schema == null) {
            return false;
        }
        if ("object".equalsIgnoreCase(schema.getType()) && schema.getProperties() != null && !schema.getProperties().isEmpty()) {
            return true;
        }
        return (schema.getAllOf() != null && !schema.getAllOf().isEmpty()) ||
               (schema.getAnyOf() != null && !schema.getAnyOf().isEmpty()) ||
               (schema.getOneOf() != null && !schema.getOneOf().isEmpty());
    }
    
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
                    log.debug("Разрешена $ref ссылка в PropertyAuthScanner: {} -> {}", ref, schemaName);
                    return resolved;
                }
            }
        }
        
        return schema;
    }

    private List<String> filterMassAssignmentBusinessContext(List<String> fields,
                                                             Map<String, Schema<?>> schemaProperties,
                                                             boolean hasStrongAuthorization,
                                                             boolean hasExplicitAccess,
                                                             boolean hasConsentEvidence,
                                                             boolean isOpenBankingOperation,
                                                             ContextAnalyzer.APIContext apiContext) {
        if (fields == null || fields.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> result = new ArrayList<>();
        boolean strongAccess = hasStrongAuthorization || hasExplicitAccess;
        boolean consentContext = hasConsentEvidence || isOpenBankingOperation;
        for (String fieldPath : fields) {
            if (fieldPath == null) {
                continue;
            }
            String lastSegment = extractLastSegment(fieldPath);
            String lowerField = lastSegment.toLowerCase(Locale.ROOT);
            Schema<?> propertySchema = getSchemaForPath(schemaProperties, fieldPath);

            boolean skip = false;

            if (isConsentField(lowerField)) {
                if (strongAccess && hasConsentEvidence) {
                    skip = true;
                } else if (consentContext && apiContext == ContextAnalyzer.APIContext.BANKING && strongAccess) {
                    skip = true;
                }
            } else if (isFinancialField(lowerField)) {
                if (consentContext && strongAccess && hasStrongNumericControls(propertySchema)) {
                    skip = true;
                }
            }

            if (!skip) {
                result.add(fieldPath);
            }
        }
        return result;
    }

    private Severity calculateMassAssignmentSeverity(Severity baseSeverity,
                                                     com.vtb.scanner.semantic.OperationClassifier.OperationType opType,
                                                     int riskScore,
                                                     List<String> fields,
                                                     boolean hasStrongAuthorization,
                                                     boolean hasExplicitAccess,
                                                     boolean hasConsentEvidence,
                                                     boolean isOpenBankingOperation,
                                                     ContextAnalyzer.APIContext apiContext) {
        Severity severity = baseSeverity.compareTo(Severity.HIGH) < 0 ? Severity.HIGH : baseSeverity;
        if (opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.REGISTER ||
            opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.CREATE) {
            severity = (severity == Severity.CRITICAL || riskScore > 120) ? Severity.CRITICAL : Severity.HIGH;
        } else if (opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.UPDATE) {
            severity = (severity == Severity.CRITICAL || riskScore > 110) ? Severity.CRITICAL : Severity.HIGH;
        }

        boolean hasPrivilegeField = fields.stream().anyMatch(this::isPrivilegeField);
        if (hasPrivilegeField) {
            return severity;
        }

        boolean strongAccess = hasStrongAuthorization || hasExplicitAccess;
        boolean consentContext = hasConsentEvidence || isOpenBankingOperation;
        boolean financialOnly = !fields.isEmpty() && fields.stream().allMatch(this::isFinancialField);
        boolean consentOnly = !fields.isEmpty() && fields.stream().allMatch(this::isConsentField);

        if (financialOnly && strongAccess && consentContext) {
            return downgradeSeverity(severity);
        }
        if (consentOnly && strongAccess && hasConsentEvidence) {
            return downgradeSeverity(severity);
        }
        if (!hasPrivilegeField && strongAccess && apiContext == ContextAnalyzer.APIContext.BANKING && consentContext) {
            return severity.compareTo(Severity.MEDIUM) <= 0 ? severity : Severity.MEDIUM;
        }
        return severity;
    }

    private int adjustMassAssignmentRiskScore(int originalRisk,
                                              Severity baseSeverity,
                                              Severity finalSeverity,
                                              boolean hasStrongAuthorization,
                                              boolean hasExplicitAccess,
                                              boolean hasConsentEvidence,
                                              boolean isOpenBankingOperation,
                                              ContextAnalyzer.APIContext apiContext) {
        if (finalSeverity.compareTo(baseSeverity) >= 0) {
            return originalRisk;
        }
        boolean strongAccess = hasStrongAuthorization || hasExplicitAccess;
        boolean consentContext = hasConsentEvidence || isOpenBankingOperation;
        int adjustment = 10;
        if (strongAccess && consentContext) {
            adjustment += 5;
        }
        if (apiContext == ContextAnalyzer.APIContext.BANKING) {
            adjustment += 5;
        }
        return Math.max(0, originalRisk - adjustment);
    }

    private String determineMassAssignmentImpact(List<String> fields, Severity severity) {
        boolean privilegeField = fields.stream().anyMatch(this::isPrivilegeField);
        if (privilegeField) {
            return severity == Severity.CRITICAL
                ? "PRIVILEGE_ESCALATION: Получение admin прав"
                : "AUTHORIZATION_BYPASS: Изменение чужих данных";
        }
        boolean financialField = fields.stream().anyMatch(this::isFinancialField);
        if (financialField) {
            return "BUSINESS_LOGIC: Финансовые лимиты и проверки";
        }
        boolean consentField = fields.stream().anyMatch(this::isConsentField);
        if (consentField) {
            return "CONSENT_MANAGEMENT: Серверное управление согласиями";
        }
        return "AUTHORIZATION_BYPASS: Требуется дополнительная валидация";
    }

    private String buildMassAssignmentEvidence(List<String> fields,
                                               boolean hasStrongAuthorization,
                                               boolean hasExplicitAccess,
                                               boolean hasConsentEvidence,
                                               boolean isOpenBankingOperation,
                                               int adjustedRisk,
                                               int originalRisk) {
        StringBuilder builder = new StringBuilder("Поля без явной серверной фильтрации: ")
            .append(String.join(", ", fields));
        builder.append(". RiskScore скорректирован с ").append(originalRisk)
            .append(" до ").append(adjustedRisk).append('.');
        if (hasStrongAuthorization || hasExplicitAccess) {
            builder.append(" Обнаружены механизмы сильной авторизации.");
        }
        if (hasConsentEvidence) {
            builder.append(" В спецификации описан consent workflow.");
        } else if (isOpenBankingOperation) {
            builder.append(" Open Banking контекст требует ручной проверки согласий.");
        }
        return builder.toString();
    }

    private Schema<?> getSchemaForPath(Map<String, Schema<?>> properties, String fieldPath) {
        if (properties == null || properties.isEmpty() || fieldPath == null) {
            return null;
        }
        Schema<?> schema = properties.get(fieldPath);
        if (schema != null) {
            return schema;
        }
        String normalized = fieldPath.replace("[]", "");
        schema = properties.get(normalized);
        if (schema != null) {
            return schema;
        }
        if (normalized.contains(".")) {
            String lastSegment = normalized.substring(normalized.lastIndexOf('.') + 1);
            schema = properties.get(lastSegment);
        }
        return schema;
    }

    private boolean hasStrongNumericControls(Schema<?> schema) {
        if (schema == null) {
            return false;
        }
        if (schema.getMinimum() != null || schema.getMaximum() != null ||
            schema.getExclusiveMinimum() != null || schema.getExclusiveMaximum() != null ||
            schema.getMultipleOf() != null) {
            return true;
        }
        if (schema.getPattern() != null && !schema.getPattern().isBlank()) {
            return true;
        }
        if (schema.getEnum() != null && !schema.getEnum().isEmpty()) {
            return true;
        }
        if (schema.getConst() != null) {
            return true;
        }
        Schema<?> items = schema.getItems();
        if (items != null && items.getEnum() != null && !items.getEnum().isEmpty()) {
            return true;
        }
        return false;
    }

    private Severity downgradeSeverity(Severity current) {
        return switch (current) {
            case CRITICAL -> Severity.HIGH;
            case HIGH -> Severity.MEDIUM;
            case MEDIUM -> Severity.LOW;
            default -> current;
        };
    }

    private boolean isPrivilegeField(String fieldPath) {
        String lower = extractLastSegment(fieldPath).toLowerCase(Locale.ROOT);
        return lower.contains("role") || lower.contains("admin") || lower.contains("privilege") ||
            lower.contains("permission") || lower.contains("scope");
    }

    private boolean isFinancialField(String fieldPath) {
        String lower = extractLastSegment(fieldPath).toLowerCase(Locale.ROOT);
        return lower.contains("amount") || lower.contains("balance") || lower.contains("price") ||
            lower.contains("cost") || lower.contains("limit") || lower.contains("threshold");
    }

    private boolean isConsentField(String fieldPath) {
        String lower = extractLastSegment(fieldPath).toLowerCase(Locale.ROOT);
        return lower.contains("consent") || lower.contains("psu") || lower.contains("tpp") ||
            lower.contains("permissions") || lower.contains("scope");
    }

    private String extractLastSegment(String fieldPath) {
        if (fieldPath == null) {
            return "";
        }
        String normalized = fieldPath.replace("[]", "");
        int idx = normalized.lastIndexOf('.');
        return idx >= 0 ? normalized.substring(idx + 1) : normalized;
    }
}

