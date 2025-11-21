package com.vtb.scanner.scanners;

import com.vtb.scanner.analysis.SchemaConstraintAnalyzer;
import com.vtb.scanner.analysis.SchemaPiiInspector;
import com.vtb.scanner.analysis.SchemaPiiInspector.PiiSignal;
import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.semantic.ContextAnalyzer;
import com.vtb.scanner.semantic.OperationClassifier;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.util.AccessControlHeuristics;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.stream.Collectors;

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
        log.info("Запуск Inventory Management Scanner (API9:2023) для {}...", targetUrl);
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null) {
            return vulnerabilities;
        }

        ContextAnalyzer.APIContext apiContext = ContextAnalyzer.detectContext(openAPI);
        SchemaConstraintAnalyzer constraintAnalyzer = new SchemaConstraintAnalyzer(openAPI);
        
        // 1. Проверка версионирования
        vulnerabilities.addAll(checkVersioning(openAPI, apiContext));
        
        // 2. Проверка deprecated endpoints
        vulnerabilities.addAll(checkDeprecated(openAPI, apiContext));
        
        // 3. Проверка документации
        vulnerabilities.addAll(checkDocumentation(openAPI, apiContext));

        // 4. Проверка серверов и окружений
        vulnerabilities.addAll(checkServerInventory(openAPI, apiContext));
        
        // 5. PII inventory
        vulnerabilities.addAll(checkSensitiveDataInventory(openAPI, parser, constraintAnalyzer, apiContext));
        
        log.info("Inventory Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkVersioning(OpenAPI openAPI, ContextAnalyzer.APIContext apiContext) {
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
            
            Severity severity = apiContext == ContextAnalyzer.APIContext.BANKING ||
                apiContext == ContextAnalyzer.APIContext.TELECOM ||
                apiContext == ContextAnalyzer.APIContext.AUTOMOTIVE ? Severity.MEDIUM : Severity.LOW;

            vulnerabilities.add(Vulnerability.builder()
                .id("INV-NO-VERSION")
                .type(VulnerabilityType.IMPROPER_INVENTORY)
                .severity(severity)
                .title("Отсутствует версия API")
                .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    tempVuln, null, false, true)) // evidence=true (точно нет версии)
                .priority(severity == Severity.MEDIUM ? 3 : 4)
                .description(
                    "В спецификации не указана версия API. " +
                    "Это затрудняет управление изменениями и обратной совместимостью."
                )
                .endpoint("spec:info.version")
                .method("META")
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
                .filter(Objects::nonNull)
                .map(server -> Optional.ofNullable(server.getUrl()).orElse(""))
                .anyMatch(url -> url.matches(".*/v\\d+.*"));
            
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
                    .endpoint("spec:servers")
                    .method("META")
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
    
    private List<Vulnerability> checkDeprecated(OpenAPI openAPI, ContextAnalyzer.APIContext apiContext) {
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
                
                // СЕМАНТИКА: deprecated критичные операции = выше severity
                OperationClassifier.OperationType opType = 
                    anyOp != null ? OperationClassifier.classify(path, "GET", anyOp) :
                    OperationClassifier.OperationType.UNKNOWN;
                
                boolean isCritical = (opType == OperationClassifier.OperationType.TRANSFER_MONEY ||
                                     opType == OperationClassifier.OperationType.PAYMENT ||
                                     opType == OperationClassifier.OperationType.ADMIN_ACTION);
                
                // УМНЫЙ расчёт: SmartAnalyzer + семантика
                Severity severity = Severity.INFO;
                if (isCritical || apiContext == ContextAnalyzer.APIContext.BANKING ||
                    apiContext == ContextAnalyzer.APIContext.TELECOM ||
                    apiContext == ContextAnalyzer.APIContext.AUTOMOTIVE) {
                    severity = Severity.MEDIUM;
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
    
    private List<Vulnerability> checkDocumentation(OpenAPI openAPI, ContextAnalyzer.APIContext apiContext) {
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
                .endpoint("spec:info.description")
                .method("META")
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

        if (openAPI.getInfo() == null || openAPI.getInfo().getContact() == null ||
            openAPI.getInfo().getContact().getEmail() == null ||
            openAPI.getInfo().getContact().getEmail().isEmpty()) {

            Severity severity = apiContext == ContextAnalyzer.APIContext.BANKING ||
                apiContext == ContextAnalyzer.APIContext.GOVERNMENT ? Severity.MEDIUM : Severity.INFO;

            vulnerabilities.add(Vulnerability.builder()
                .id("INV-NO-CONTACT")
                .type(VulnerabilityType.IMPROPER_INVENTORY)
                .severity(severity)
                .title("Не указаны контактные данные по API")
                .description(
                    "В info.contact не указан email контакта. При инцидентах будет сложно уведомить ответственную команду."
                )
                .endpoint("spec:info.contact.email")
                .method("META")
                .recommendation(
                    "Добавьте info.contact.email и, при возможности, info.contact.name/phone. Это ускорит реакцию на уязвимости."
                )
                .owaspCategory("API9:2023 - Improper Inventory Management")
                .evidence("contact.email отсутствует")
                .build());
        }

        if (openAPI.getInfo() == null || openAPI.getInfo().getTermsOfService() == null ||
            openAPI.getInfo().getTermsOfService().isEmpty()) {
            vulnerabilities.add(Vulnerability.builder()
                .id("INV-NO-TOS")
                .type(VulnerabilityType.IMPROPER_INVENTORY)
                .severity(Severity.INFO)
                .title("Не указаны условия использования API")
                .description("В info.termsOfService не указан URL с условиями использования API.")
                .endpoint("spec:info.termsOfService")
                .method("META")
                .recommendation("Укажите info.termsOfService со ссылкой на SLA/политику использования API.")
                .owaspCategory("API9:2023 - Improper Inventory Management")
                .evidence("termsOfService отсутствует")
                .build());
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> checkServerInventory(OpenAPI openAPI, ContextAnalyzer.APIContext apiContext) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        if (openAPI.getServers() == null || openAPI.getServers().isEmpty()) {
            return vulnerabilities;
        }

        for (int i = 0; i < openAPI.getServers().size(); i++) {
            var server = openAPI.getServers().get(i);
            String url = server != null && server.getUrl() != null ? server.getUrl() : "";
            String lowerUrl = url.toLowerCase(Locale.ROOT);

            if (lowerUrl.contains("localhost") || lowerUrl.contains("127.0.0.1") || lowerUrl.contains("internal")) {
                Vulnerability temp = Vulnerability.builder()
                    .type(VulnerabilityType.IMPROPER_INVENTORY)
                    .severity(Severity.MEDIUM)
                    .build();
                int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(temp, null, false, true);

                vulnerabilities.add(Vulnerability.builder()
                    .id("INV-LOCAL-SERVER-" + i)
                    .type(VulnerabilityType.IMPROPER_INVENTORY)
                    .severity(Severity.MEDIUM)
                    .confidence(confidence)
                    .priority(3)
                    .title("Сервер с локальным/внутренним URL в спецификации")
                    .description(String.format("Server URL '%s' содержит localhost/internal. Убедитесь, что этот сервер не утечет в production документацию.", url))
                    .endpoint("server:" + i)
                    .method("N/A")
                    .recommendation("Удалите внутренние URL из публичной спецификации или отметьте их как internal.")
                    .owaspCategory("API9:2023 - Improper Inventory Management")
                    .evidence(url)
                    .build());
            }

            if (lowerUrl.contains("dev") || lowerUrl.contains("test") || lowerUrl.contains("qa") || lowerUrl.contains("stage")) {
                Severity severity = apiContext == ContextAnalyzer.APIContext.BANKING ||
                    apiContext == ContextAnalyzer.APIContext.TELECOM ? Severity.MEDIUM : Severity.INFO;
                vulnerabilities.add(Vulnerability.builder()
                    .id("INV-NONPROD-EXPOSED-" + i)
                    .type(VulnerabilityType.IMPROPER_INVENTORY)
                    .severity(severity)
                    .title("В спецификации указан non-prod сервер")
                    .description(String.format("Server URL '%s' указывает на dev/test окружение. Проверьте, что спецификация доступна ограниченному кругу пользователей.", url))
                    .endpoint("server:" + i)
                    .method("N/A")
                    .recommendation("Храните dev/test endpoints в отдельной спецификации или помечайте их как internal.")
                    .owaspCategory("API9:2023 - Improper Inventory Management")
                    .evidence(url)
                    .build());
            }
        }

        return vulnerabilities;
    }

    private List<Vulnerability> checkSensitiveDataInventory(OpenAPI openAPI,
                                                            OpenAPIParser parser,
                                                            SchemaConstraintAnalyzer analyzer,
                                                            ContextAnalyzer.APIContext apiContext) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        if (openAPI.getPaths() == null || analyzer == null) {
            return vulnerabilities;
        }
        Set<String> reported = new HashSet<>();
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem item = entry.getValue();
            if (item == null) {
                continue;
            }
            vulnerabilities.addAll(checkOperationData(path, "GET", item.getGet(), openAPI, parser, analyzer, reported, apiContext));
            vulnerabilities.addAll(checkOperationData(path, "POST", item.getPost(), openAPI, parser, analyzer, reported, apiContext));
            vulnerabilities.addAll(checkOperationData(path, "PUT", item.getPut(), openAPI, parser, analyzer, reported, apiContext));
            vulnerabilities.addAll(checkOperationData(path, "DELETE", item.getDelete(), openAPI, parser, analyzer, reported, apiContext));
            vulnerabilities.addAll(checkOperationData(path, "PATCH", item.getPatch(), openAPI, parser, analyzer, reported, apiContext));
        }
        return vulnerabilities;
    }

    private List<Vulnerability> checkOperationData(String path,
                                                   String method,
                                                   Operation operation,
                                                   OpenAPI openAPI,
                                                   OpenAPIParser parser,
                                                   SchemaConstraintAnalyzer analyzer,
                                                   Set<String> reported,
                                                   ContextAnalyzer.APIContext apiContext) {
        if (operation == null) {
            return Collections.emptyList();
        }

        List<PiiSignal> signals = new ArrayList<>();
        if (operation.getParameters() != null) {
            for (Parameter parameter : operation.getParameters()) {
                if (parameter == null) {
                    continue;
                }
                PiiSignal signal = SchemaPiiInspector.inspectParameter(parameter, analyzer);
                if (signal != null) {
                    signals.add(signal);
                }
            }
        }
        if (operation.getRequestBody() != null && operation.getRequestBody().getContent() != null) {
            operation.getRequestBody().getContent().values().forEach(media -> {
                if (media != null && media.getSchema() != null) {
                    signals.addAll(SchemaPiiInspector.collectFromSchema(media.getSchema(), analyzer, "body"));
                }
            });
        }
        if (operation.getResponses() != null) {
            operation.getResponses().forEach((status, response) -> {
                if (response != null && response.getContent() != null) {
                    response.getContent().values().forEach(media -> {
                        if (media != null && media.getSchema() != null) {
                            signals.addAll(SchemaPiiInspector.collectFromSchema(media.getSchema(), analyzer, "response." + status));
                        }
                    });
                }
            });
        }

        Map<String, PiiSignal> uniqueSignals = signals.stream()
            .filter(Objects::nonNull)
            .collect(Collectors.toMap(PiiSignal::pointer, s -> s, (a, b) -> a, LinkedHashMap::new));

        if (uniqueSignals.isEmpty()) {
            return Collections.emptyList();
        }

        String dedupeKey = path + "|" + method + "|PII";
        if (!reported.add(dedupeKey)) {
            return Collections.emptyList();
        }

        boolean hasHighRisk = uniqueSignals.values().stream().anyMatch(PiiSignal::highRisk);
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(path, method, operation, openAPI);
        boolean requiresAuth = parser != null && parser.requiresAuthentication(operation);
        boolean hasStrongAuthorization = AccessControlHeuristics.hasStrongAuthorization(operation, openAPI);
        boolean hasExplicitAccess = AccessControlHeuristics.hasExplicitAccessControl(operation, path, openAPI);

        Severity severity = hasHighRisk ? Severity.HIGH : Severity.MEDIUM;
        if (!requiresAuth || (!hasStrongAuthorization && !hasExplicitAccess)) {
            severity = severity == Severity.HIGH ? Severity.CRITICAL : Severity.HIGH;
        }
        if (apiContext == ContextAnalyzer.APIContext.BANKING ||
            apiContext == ContextAnalyzer.APIContext.GOVERNMENT) {
            severity = severity == Severity.CRITICAL ? severity : Severity.HIGH;
        }

        Vulnerability temp = Vulnerability.builder()
            .type(VulnerabilityType.EXCESSIVE_DATA_EXPOSURE)
            .severity(severity)
            .riskScore(riskScore)
            .build();
        int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(temp, operation, false, true);
        int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(temp, confidence);

        String evidence = uniqueSignals.values().stream()
            .map(PiiSignal::evidence)
            .collect(Collectors.joining("; "));

        Vulnerability vulnerability = Vulnerability.builder()
            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                VulnerabilityType.EXCESSIVE_DATA_EXPOSURE, path, method, null, "PII inventory signal"))
            .type(VulnerabilityType.EXCESSIVE_DATA_EXPOSURE)
            .severity(severity)
            .riskScore(riskScore)
            .confidence(confidence)
            .priority(priority)
            .title("PII поля в спецификации без явной классификации")
            .description("Операция " + method + " " + path + " содержит чувствительные поля (PII). Проверьте, что они защищены аутентификацией и отмечены как конфиденциальные.")
            .endpoint(path)
            .method(method)
            .recommendation("Добавьте маркировку/маскирование PII, укажите требования к хранению и доступу, запретите публикацию реальных данных в примерах.")
            .owaspCategory("API3:2023 - Excessive Data Exposure")
            .evidence(evidence)
            .build();
        return List.of(vulnerability);
    }
}

