package com.vtb.scanner.scanners;

import com.vtb.scanner.config.ScannerConfig;
import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.heuristics.EnhancedRules;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Сканер для обнаружения уязвимостей аутентификации и авторизации
 * API2:2023 - Broken Authentication
 * API5:2023 - Broken Function Level Authorization
 */
@Slf4j
public class AuthScanner implements VulnerabilityScanner {
    
    private final String targetUrl;
    private final ScannerConfig config;
    private final List<String> sensitivePaths;
    
    public AuthScanner(String targetUrl) {
        this.targetUrl = targetUrl;
        
        // Загружаем конфигурацию (убираем хардкод!)
        try {
            this.config = ScannerConfig.load();
            
            // Собираем все чувствительные пути из конфига
            this.sensitivePaths = new ArrayList<>();
            if (config.getSensitivePaths() != null) {
                config.getSensitivePaths().values().forEach(sensitivePaths::addAll);
            }
        } catch (Exception e) {
            log.warn("Не удалось загрузить конфигурацию, используем defaults: {}", e.getMessage());
            throw e;
        }
    }
    
    @Override
    public List<Vulnerability> scan(OpenAPI openAPI, OpenAPIParser parser) {
        log.info("Запуск Auth Scanner...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null) {
            return vulnerabilities;
        }
        
        // Проверяем наличие security schemes
        vulnerabilities.addAll(checkSecuritySchemes(openAPI));
        
        // Проверяем эндпоинты
        if (openAPI.getPaths() != null) {
            for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
                String path = entry.getKey();
                PathItem pathItem = entry.getValue();
                
                vulnerabilities.addAll(checkPathAuthentication(path, pathItem, parser, openAPI));
            }
        }
        
        log.info("Auth Scanner завершен. Найдено уязвимостей: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    /**
     * Проверка security schemes
     */
    private List<Vulnerability> checkSecuritySchemes(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getComponents() == null) {
            return vulnerabilities;
        }
        
        // Проверяем есть ли вообще security schemes
        if (openAPI.getComponents().getSecuritySchemes() == null ||
            openAPI.getComponents().getSecuritySchemes().isEmpty()) {
            
            vulnerabilities.add(Vulnerability.builder()
                .id("AUTH-NO-SCHEME")
                .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                .severity(Severity.CRITICAL)
                .title("Отсутствуют схемы аутентификации")
                .description("В спецификации API не определены схемы аутентификации (securitySchemes)")
                .endpoint("N/A")
                .method("N/A")
                .recommendation("Добавьте security schemes (OAuth2, Bearer, API Key) в компоненты спецификации")
                .owaspCategory("API2:2023 - Broken Authentication")
                .evidence("Секция components.securitySchemes отсутствует или пуста")
                .build());
            
            return vulnerabilities;
        }
        
        // Проверяем типы схем
        Map<String, SecurityScheme> schemes = openAPI.getComponents().getSecuritySchemes();
        for (Map.Entry<String, SecurityScheme> entry : schemes.entrySet()) {
            String schemeName = entry.getKey();
            SecurityScheme scheme = entry.getValue();
            
            // Проверяем слабые схемы
            if (scheme.getType() == SecurityScheme.Type.HTTP && 
                "basic".equalsIgnoreCase(scheme.getScheme())) {
                
                vulnerabilities.add(Vulnerability.builder()
                    .id("AUTH-WEAK-BASIC")
                    .type(VulnerabilityType.WEAK_AUTHENTICATION)
                    .severity(Severity.MEDIUM)
                    .title("Использование Basic Authentication")
                    .description("Схема '" + schemeName + "' использует Basic Auth, который передает " +
                                "credentials в base64 (легко декодируется)")
                    .endpoint("scheme:" + schemeName)
                    .method("DEFINITION")
                    .recommendation("Используйте более безопасные схемы: OAuth2, JWT Bearer Token")
                    .owaspCategory("API2:2023 - Broken Authentication")
                    .evidence("Обнаружена Basic Auth схема: " + schemeName)
                    .build());
            }
            
            // Проверяем API Key в query
            if (scheme.getType() == SecurityScheme.Type.APIKEY && 
                SecurityScheme.In.QUERY.equals(scheme.getIn())) {
                
                vulnerabilities.add(Vulnerability.builder()
                    .id("AUTH-APIKEY-QUERY")
                    .type(VulnerabilityType.WEAK_AUTHENTICATION)
                    .severity(Severity.HIGH)
                    .title("API Key в query параметрах")
                    .description("Схема '" + schemeName + "' передает API ключ в URL query string")
                    .endpoint("scheme:" + schemeName)
                    .method("DEFINITION")
                    .recommendation("Передавайте API ключ в заголовках, не в URL")
                    .owaspCategory("API2:2023 - Broken Authentication")
                    .evidence("API Key передается в query: " + scheme.getName())
                    .build());
            }
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка аутентификации для пути
     */
    private List<Vulnerability> checkPathAuthentication(String path, PathItem pathItem, OpenAPIParser parser, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Проверяем каждый метод
        if (pathItem.getGet() != null) {
            vulnerabilities.addAll(checkOperationAuth(path, "GET", pathItem.getGet(), parser, openAPI));
        }
        if (pathItem.getPost() != null) {
            vulnerabilities.addAll(checkOperationAuth(path, "POST", pathItem.getPost(), parser, openAPI));
        }
        if (pathItem.getPut() != null) {
            vulnerabilities.addAll(checkOperationAuth(path, "PUT", pathItem.getPut(), parser, openAPI));
        }
        if (pathItem.getPatch() != null) {
            vulnerabilities.addAll(checkOperationAuth(path, "PATCH", pathItem.getPatch(), parser, openAPI));
        }
        if (pathItem.getDelete() != null) {
            vulnerabilities.addAll(checkOperationAuth(path, "DELETE", pathItem.getDelete(), parser, openAPI));
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка аутентификации для операции
     * 
     * С СЕМАНТИЧЕСКИМ АНАЛИЗОМ!
     */
    private List<Vulnerability> checkOperationAuth(String path, String method, Operation operation, 
                                                     OpenAPIParser parser, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // СЕМАНТИЧЕСКИЙ АНАЛИЗ - понимаем ТИП операции!
        com.vtb.scanner.semantic.OperationClassifier.OperationType opType = 
            com.vtb.scanner.semantic.OperationClassifier.classify(path, method, operation);
        
        // ИСПОЛЬЗУЕМ SmartAnalyzer для расчёта риска!
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
            path, method, operation, parser.getOpenAPI());
        
        boolean requiresAuth = parser.requiresAuthentication(operation);
        boolean isSensitivePath = isSensitivePath(path);
        boolean isModifyingMethod = isModifyingMethod(method);
        
        // НОВЫЕ ПРОВЕРКИ: Crypto/Wallet endpoints + JWT Claims
        if (operation.getParameters() != null) {
            for (io.swagger.v3.oas.models.parameters.Parameter param : operation.getParameters()) {
                if (EnhancedRules.isCryptoRisk(param) && !requiresAuth) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.BROKEN_AUTHENTICATION, path, method, param.getName(),
                            "Crypto operation without authentication"))
                        .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                        .severity(Severity.CRITICAL)
                        .title("Криптовалютная операция без аутентификации")
                        .description("Параметр '" + param.getName() + "' связан с криптовалютами/blockchain, " +
                                   "но эндпоинт не защищен аутентификацией!")
                        .endpoint(path)
                        .method(method)
                        .recommendation("ОБЯЗАТЕЛЬНО добавьте: аутентификацию + 2FA + transaction signing")
                        .owaspCategory("API2:2023 - Broken Authentication (Crypto)")
                        .evidence("Crypto параметр: " + param.getName())
                        .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                            Vulnerability.builder()
                                .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                                .severity(Severity.CRITICAL)
                                .build(),
                            operation, false, true)) // hasEvidence=true (нашли крипто параметр!)
                        .priority(1)
                        .build());
                }
                
                if (EnhancedRules.isRussianPaymentRisk(param) && !requiresAuth) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.BROKEN_AUTHENTICATION, path, method, param.getName(),
                            "Russian payment system without authentication"))
                        .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                        .severity(Severity.CRITICAL)
                        .title("Российская платежная система без аутентификации")
                        .description("Параметр '" + param.getName() + "' связан с российскими платежами " +
                                   "(СБП/МИР/QIWI), но эндпоинт не защищен!")
                        .endpoint(path)
                        .method(method)
                        .recommendation("ОБЯЗАТЕЛЬНО: аутентификация + 2FA + ФЗ-152 + ФЗ-115 (AML)")
                        .owaspCategory("API2:2023 - Broken Authentication (Russian Payments)")
                        .evidence("Платежный параметр: " + param.getName())
                        .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                            Vulnerability.builder()
                                .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                                .severity(Severity.CRITICAL)
                                .build(),
                            operation, false, true)) // hasEvidence=true
                        .priority(1)
                        .build());
                }
            }
        }
        
        // НОВОЕ: JWT Claims проверка (опасные claims в schema)
        if (operation.getRequestBody() != null && 
            operation.getRequestBody().getContent() != null) {
            var content = operation.getRequestBody().getContent().get("application/json");
            if (content != null && content.getSchema() != null) {
                // КРИТИЧНО: Разрешаем $ref ссылки перед анализом
                io.swagger.v3.oas.models.media.Schema schema = resolveSchemaRef(content.getSchema(), openAPI);
                List<String> dangerousClaims = new ArrayList<>(EnhancedRules.findDangerousJWTClaims(schema));
                dangerousClaims.removeIf(claim -> isAllowedJwtClaim(claim, path, operation));
                
                if (!dangerousClaims.isEmpty()) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.WEAK_AUTHENTICATION, path, method, null,
                            "Dangerous JWT claims in request"))
                        .type(VulnerabilityType.WEAK_AUTHENTICATION)
                        .severity(Severity.HIGH)
                        .title("Опасные JWT claims в запросе")
                        .description(String.format(
                            "Request body содержит опасные JWT claims: %s\n\n" +
                            "Риски:\n" +
                            "• 'alg: none' → bypass signature\n" +
                            "• 'kid' injection → RCE\n" +
                            "• 'jku'/'x5u' → SSRF\n" +
                            "• 'role'/'admin' в payload → privilege escalation\n\n" +
                            "Клиент НЕ должен контролировать эти поля!",
                            String.join(", ", dangerousClaims)
                        ))
                        .endpoint(path)
                        .method(method)
                        .recommendation(
                            "JWT Security:\n\n" +
                            "1. НИКОГДА не принимайте 'alg' от клиента!\n" +
                            "2. 'kid' - валидация whitelist (не путь к файлу!)\n" +
                            "3. 'jku'/'x5u' - запретите или strict whitelist\n" +
                            "4. 'role'/'permissions' - ТОЛЬКО на сервере!\n" +
                            "5. Используйте HS256/RS256, НЕ 'none'\n" +
                            "6. Проверяйте signature ВСЕГДА\n" +
                            "7. exp/nbf/iat - обязательны"
                        )
                        .owaspCategory("API2:2023 - Broken Authentication (JWT)")
                        .evidence("Опасные claims: " + String.join(", ", dangerousClaims))
                        .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                            Vulnerability.builder()
                                .type(VulnerabilityType.WEAK_AUTHENTICATION)
                                .severity(Severity.HIGH)
                                .build(),
                            operation, false, true)) // hasEvidence=true
                        .priority(2)
                        .build());
                }
            }
        }
        
        // КОНТЕКСТНАЯ ПРОВЕРКА - для разных типов операций разные требования!
        List<String> requirements = 
            com.vtb.scanner.semantic.OperationClassifier.getRequirements(opType);
        
        // Проверяем выполнены ли требования
        if (!requiresAuth && requirements.contains("ОБЯЗАТЕЛЬНА аутентификация")) {
            // Severity через SmartAnalyzer (96 факторов!) + повышение за отсутствие auth!
            Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
            
            // Повышаем severity т.к. нет аутентификации!
            Severity severity = switch (baseSeverity) {
                case INFO -> Severity.LOW;
                case LOW -> Severity.MEDIUM;
                case MEDIUM -> Severity.HIGH;
                case HIGH -> Severity.CRITICAL;
                case CRITICAL -> Severity.CRITICAL;
            };
            
            // Уязвимость с семантическим описанием!
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BROKEN_AUTHENTICATION, path, method, null,
                    "Semantic operation without authentication"))
                .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                .severity(severity)
                .title("Операция типа '" + opType + "' БЕЗ аутентификации!")
                .description(String.format(
                    "Эндпоинт %s выполняет операцию типа '%s'.\n\n" +
                    "Требования для этого типа:\n%s\n\n" +
                    "НЕ ВЫПОЛНЕНО: Нет аутентификации!",
                    path, opType, String.join("\n", requirements)
                ))
                .endpoint(path)
                .method(method)
                .recommendation(String.join("\n", requirements))
                .owaspCategory("API2:2023 - Broken Authentication (Semantic)")
                .evidence("Тип операции: " + opType + ", Risk Score: " + riskScore)
                .riskScore(riskScore) // Сохраняем risk score!
                .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    Vulnerability.builder()
                        .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .build(),
                    operation,
                    false, // корреляция
                    true   // evidence (есть risk score!)
                ))
                .priority(severity == Severity.CRITICAL ? 1 : 2)
                .impactLevel(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateImpact(
                    Vulnerability.builder().type(VulnerabilityType.BROKEN_AUTHENTICATION).build()
                ))
                .build());
            
            return vulnerabilities; // Уже добавили семантическую, выходим
        }
        
        // Старая логика (если семантика не сработала) - используем уже объявленные переменные
        // Критично: чувствительный эндпоинт без аутентификации
        if (isSensitivePath && !requiresAuth) {
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BROKEN_AUTHENTICATION, path, method, null,
                    "Sensitive endpoint without authentication"))
                .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                .severity(Severity.CRITICAL)
                .title("Чувствительный эндпоинт без аутентификации")
                .description("Эндпоинт " + path + " кажется чувствительным, но не защищен аутентификацией")
                .endpoint(path)
                .method(method)
                .recommendation("Добавьте security requirement для этого эндпоинта")
                .owaspCategory("API2:2023 - Broken Authentication")
                .evidence("Путь содержит чувствительное слово, но security не определена")
                .build());
        }
        
        // Высоко: модифицирующие методы без аутентификации
        if (isModifyingMethod && !requiresAuth) {
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Modifying method without authentication"))
                .type(VulnerabilityType.BFLA)
                .severity(Severity.HIGH)
                .title("Модифицирующий метод без аутентификации")
                .description("Метод " + method + " для " + path + " изменяет данные, но не требует аутентификации")
                .endpoint(path)
                .method(method)
                .recommendation("Все методы POST/PUT/DELETE/PATCH должны требовать аутентификацию")
                .owaspCategory("API5:2023 - Broken Function Level Authorization")
                .evidence("Метод " + method + " без security")
                .build());
        }
        
        // Проверка на debug/test эндпоинты
        if (path.toLowerCase().contains("debug") || 
            path.toLowerCase().contains("test") ||
            path.toLowerCase().contains("admin") && !requiresAuth) {
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.DEBUG_ENDPOINT, path, method, null,
                    "Open debug/admin endpoint"))
                .type(VulnerabilityType.DEBUG_ENDPOINT)
                .severity(Severity.CRITICAL)
                .title("Открытый debug/admin эндпоинт")
                .description("Обнаружен debug/admin эндпоинт без защиты: " + path)
                .endpoint(path)
                .method(method)
                .recommendation("Удалите debug эндпоинты из production или защитите их строгой аутентификацией")
                .owaspCategory("API8:2023 - Security Misconfiguration")
                .evidence("Путь содержит 'debug', 'test' или 'admin'")
                .build());
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверить является ли путь чувствительным (из конфига!)
     */
    private boolean isSensitivePath(String path) {
        String lowerPath = path.toLowerCase();
        return sensitivePaths.stream().anyMatch(lowerPath::contains);
    }
    
    /**
     * Проверить является ли метод модифицирующим
     */
    private boolean isModifyingMethod(String method) {
        return method.equals("POST") || method.equals("PUT") || 
               method.equals("DELETE") || method.equals("PATCH");
    }
    
    /**
     * Разрешить $ref ссылку на schema
     * КРИТИЧНО: Гарантирует анализ всех схем даже при ошибках resolve в библиотеке!
     */
    private io.swagger.v3.oas.models.media.Schema resolveSchemaRef(
            io.swagger.v3.oas.models.media.Schema schema, OpenAPI openAPI) {
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
                io.swagger.v3.oas.models.media.Schema resolved = 
                    openAPI.getComponents().getSchemas().get(schemaName);
                if (resolved != null) {
                    log.debug("Разрешена $ref ссылка в AuthScanner: {} -> {}", ref, schemaName);
                    return resolved;
                }
            }
        }
        
        return schema;
    }

    private boolean isAllowedJwtClaim(String claim, String path, Operation operation) {
        if (claim == null) {
            return false;
        }
        String lowerClaim = claim.toLowerCase(Locale.ROOT);
        String lowerPath = path != null ? path.toLowerCase(Locale.ROOT) : "";
        StringBuilder text = new StringBuilder();
        if (operation != null) {
            if (operation.getSummary() != null) {
                text.append(operation.getSummary().toLowerCase(Locale.ROOT)).append(' ');
            }
            if (operation.getDescription() != null) {
                text.append(operation.getDescription().toLowerCase(Locale.ROOT));
            }
        }
        String combined = text.toString();

        if ("permissions".equals(lowerClaim) || lowerClaim.contains("scope")) {
            return lowerPath.contains("consent") || lowerPath.contains("payment-consents") ||
                   combined.contains("consent") || combined.contains("open banking");
        }
        if ("client_id".equals(lowerClaim)) {
            return lowerPath.contains("auth") || lowerPath.contains("token") || combined.contains("token");
        }
        return false;
    }
}

