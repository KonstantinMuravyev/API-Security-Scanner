package com.vtb.scanner.scanners;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.heuristics.EnhancedRules;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * API4:2023 - Unrestricted Resource Consumption
 * Проверяет отсутствие rate limiting, пагинации, timeout
 */
@Slf4j
public class ResourceScanner implements VulnerabilityScanner {
    
    private final String targetUrl;
    
    public ResourceScanner(String targetUrl) {
        this.targetUrl = targetUrl;
    }
    
    @Override
    public List<Vulnerability> scan(OpenAPI openAPI, OpenAPIParser parser) {
        log.debug("Запуск Resource Consumption Scanner (API4:2023)...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // Проверяем ВСЕ методы HTTP!
            if (pathItem.getGet() != null) {
                vulnerabilities.addAll(checkResourceLimits(path, "GET", pathItem.getGet(), openAPI));
            }
            if (pathItem.getPost() != null) {
                vulnerabilities.addAll(checkResourceLimits(path, "POST", pathItem.getPost(), openAPI));
            }
            if (pathItem.getPut() != null) {
                vulnerabilities.addAll(checkResourceLimits(path, "PUT", pathItem.getPut(), openAPI));
            }
            if (pathItem.getDelete() != null) {
                vulnerabilities.addAll(checkResourceLimits(path, "DELETE", pathItem.getDelete(), openAPI));
            }
            if (pathItem.getPatch() != null) {
                vulnerabilities.addAll(checkResourceLimits(path, "PATCH", pathItem.getPatch(), openAPI));
            }
        }
        
        log.debug("Resource Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkResourceLimits(String path, String method, Operation operation, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (operation == null) {
            return vulnerabilities;
        }
        
        // СЕМАНТИЧЕСКИЙ АНАЛИЗ - для финансовых операций rate limit ОБЯЗАТЕЛЕН!
        com.vtb.scanner.semantic.OperationClassifier.OperationType opType = 
            com.vtb.scanner.semantic.OperationClassifier.classify(path, method, operation);
        
        // ИСПОЛЬЗУЕМ SmartAnalyzer для контекста!
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
            path, method, operation, openAPI);
        
        boolean isFinancial = (opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.TRANSFER_MONEY ||
                              opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.PAYMENT);
        
        String lowerPath = path != null ? path.toLowerCase(Locale.ROOT) : "";
        boolean isConsentFlow = lowerPath.contains("consent");
        boolean isTokenEndpoint = lowerPath.contains("bank-token") || lowerPath.contains("/auth/") || lowerPath.contains("token");
        boolean isCatalogEndpoint = lowerPath.contains("/products") || lowerPath.contains("catalog");

        boolean hasRateLimit = hasRateLimiting(operation);
        boolean hasPagination = hasPagination(operation);
        boolean hasTimeout = hasTimeoutMention(operation);
        boolean requiresAuth = operation != null && operation.getSecurity() != null && !operation.getSecurity().isEmpty();
        
        // 1. Отсутствие rate limiting (СЕМАНТИКА + SmartAnalyzer!)
        // Проверяем все модифицирующие методы и GET для финансовых операций
        if (!isConsentFlow && !isTokenEndpoint && !hasRateLimit && (method.equals("POST") || method.equals("PUT") || 
                              method.equals("DELETE") || method.equals("PATCH") ||
                              (method.equals("GET") && isFinancial))) {
            // Базовая severity от SmartAnalyzer (учитывает контекст)
            Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
            
            // Для финансовых - гарантированно CRITICAL
            Severity severity = Severity.MEDIUM;
            if (isFinancial) {
                severity = Severity.CRITICAL;
                if (requiresAuth) {
                    severity = Severity.HIGH;
                }
            } else {
                severity = baseSeverity.compareTo(Severity.MEDIUM) < 0 ? Severity.MEDIUM : baseSeverity;
                if (requiresAuth) {
                    severity = Severity.MEDIUM;
                }
            }
            
            // ДИНАМИЧЕСКИЙ расчет!
            Vulnerability tempVuln = Vulnerability.builder()
                .type(VulnerabilityType.RATE_LIMIT_MISSING)
                .severity(severity)
                .build();
            
            int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                tempVuln, operation, false, false);
            
            int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                tempVuln, confidence);
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.RATE_LIMIT_MISSING, path, method, null,
                    "Rate limiting missing"))
                .type(VulnerabilityType.RATE_LIMIT_MISSING)
                .severity(severity)
                .title("Отсутствует rate limiting")
                .confidence(confidence)
                .priority(priority)
                .impactLevel(isFinancial ? "FINANCIAL_FRAUD: Массовые платежи" : "DOS_RISK: Перегрузка")
                .description(String.format(
                    "Эндпоинт %s %s не описывает механизм rate limiting. " +
                    "Возможна перегрузка системы множественными запросами.",
                    method, path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Реализуйте rate limiting (например, 100 requests/minute). " +
                    "Возвращайте HTTP 429 Too Many Requests. " +
                    "Используйте headers: X-RateLimit-Limit, X-RateLimit-Remaining."
                )
                .owaspCategory("API4:2023 - Unrestricted Resource Consumption")
                .evidence("Нет упоминаний rate limit и response 429. Risk Score: " + riskScore)
                .riskScore(riskScore)
                .build());
        }
        
        // 2. GET без пагинации (список данных)
        if (method.equals("GET") && !hasPagination && !isCatalogEndpoint && looksLikeListEndpoint(path)) {
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION, path, method, null,
                    "Pagination missing"))
                .type(VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION)
                .severity(Severity.MEDIUM)
                .title("Отсутствует пагинация")
                .description(String.format(
                    "Эндпоинт %s возвращает список без ограничений. " +
                    "Может вернуть миллионы записей → DoS.",
                    path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Добавьте пагинацию: параметры limit/offset или page/size. " +
                    "Установите разумный лимит по умолчанию (например, 100)."
                )
                .owaspCategory("API4:2023 - Unrestricted Resource Consumption")
                .evidence("Нет параметров пагинации (limit, page, offset)")
                .build());
        }
        
        // НОВЫЕ ПРОВЕРКИ: Path Traversal, NoSQL, Template Injection
        if (operation.getParameters() != null) {
            for (io.swagger.v3.oas.models.parameters.Parameter param : operation.getParameters()) {
                if (EnhancedRules.isPathTraversalRisk(param)) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, param.getName(),
                            "Path Traversal/LFI risk"))
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(Severity.HIGH)
                        .title("Риск Path Traversal/LFI")
                        .description("Параметр '" + param.getName() + "' может использоваться для чтения файлов " +
                                   "(../../etc/passwd). Проверьте валидацию!")
                        .endpoint(path)
                        .method(method)
                        .recommendation("Валидируйте путь: whitelist разрешенных файлов + Path.normalize() + " +
                                      "запретите '..' в пути")
                        .owaspCategory("API8:2023 - Security Misconfiguration (Path Traversal)")
                        .evidence("Параметр файла/пути: " + param.getName())
                        .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                            Vulnerability.builder()
                                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                                .severity(Severity.HIGH)
                                .build(),
                            operation, false, true))
                        .priority(2)
                        .build());
                }
                
                if (EnhancedRules.isNoSQLRisk(param)) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.NOSQL_INJECTION, path, method, param.getName(),
                            "NoSQL Injection risk"))
                        .type(VulnerabilityType.NOSQL_INJECTION)
                        .severity(Severity.HIGH)
                        .title("Риск NoSQL Injection")
                        .description("Параметр '" + param.getName() + "' может быть уязвим к NoSQL injection " +
                                   "($where, $regex, $gt, etc). MongoDB особенно уязвим!")
                        .endpoint(path)
                        .method(method)
                        .recommendation("Используйте prepared queries + валидация типов + whitelist операторов. " +
                                      "НЕ передавайте объекты напрямую в MongoDB!")
                        .owaspCategory("Injection Attacks (NoSQL)")
                        .evidence("NoSQL параметр: " + param.getName())
                        .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                            Vulnerability.builder()
                                .type(VulnerabilityType.NOSQL_INJECTION)
                                .severity(Severity.HIGH)
                                .build(),
                            operation, false, true))
                        .priority(2)
                        .build());
                }
                
                if (EnhancedRules.isTemplateInjectionRisk(param)) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, param.getName(),
                            "Server-Side Template Injection (SSTI) risk"))
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(Severity.CRITICAL)
                        .title("Риск Server-Side Template Injection (SSTI)")
                        .description("Параметр '" + param.getName() + "' может использоваться в template engine. " +
                                   "SSTI может привести к RCE!")
                        .endpoint(path)
                        .method(method)
                        .recommendation("НИКОГДА не передавайте user input в templates! Используйте sandboxed режим. " +
                                      "Для Jinja2: use SandboxedEnvironment")
                        .owaspCategory("Injection Attacks (SSTI → RCE)")
                        .evidence("Template параметр: " + param.getName())
                        .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                            Vulnerability.builder()
                                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                                .severity(Severity.CRITICAL)
                                .build(),
                            operation, false, true))
                        .priority(1)
                        .build());
                }
                
                if (EnhancedRules.isLDAPRisk(param)) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.LDAP_INJECTION, path, method, param.getName(),
                            "LDAP Injection risk"))
                        .type(VulnerabilityType.LDAP_INJECTION)
                        .severity(Severity.HIGH)
                        .title("Риск LDAP Injection")
                        .description("Параметр '" + param.getName() + "' используется в LDAP запросе. " +
                                   "Можно обойти авторизацию: (uid=*)(password=*)")
                        .endpoint(path)
                        .method(method)
                        .recommendation("Escape спецсимволы: *, (, ), \\, NUL. Используйте prepared statements.")
                        .owaspCategory("Injection Attacks (LDAP)")
                        .evidence("LDAP параметр: " + param.getName())
                        .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                            Vulnerability.builder()
                                .type(VulnerabilityType.LDAP_INJECTION)
                                .severity(Severity.HIGH)
                                .build(),
                            operation, false, true))
                        .priority(2)
                        .build());
                }
                
                if (EnhancedRules.isDeserializationRisk(param)) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, param.getName(),
                            "Deserialization risk"))
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(Severity.CRITICAL)
                        .title("Риск Insecure Deserialization")
                        .description("Параметр '" + param.getName() + "' может десериализовать untrusted data. " +
                                   "Ведет к RCE через Java/Python/Ruby gadget chains!")
                        .endpoint(path)
                        .method(method)
                        .recommendation("НЕ десериализуйте untrusted data! Используйте JSON. " +
                                      "Если необходимо: whitelist классов + digital signature.")
                        .owaspCategory("Insecure Deserialization → RCE")
                        .evidence("Deserialization параметр: " + param.getName())
                        .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                            Vulnerability.builder()
                                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                                .severity(Severity.CRITICAL)
                                .build(),
                            operation, false, true))
                        .priority(1)
                        .build());
                }
                
                // НОВОЕ: ReDoS (Regular Expression Denial of Service)
                if (EnhancedRules.isReDoSRisk(param)) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION, path, method, param.getName(),
                            "ReDoS (Regular Expression Denial of Service) risk"))
                        .type(VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION)
                        .severity(Severity.HIGH)
                        .title("Риск ReDoS (Regular Expression DoS)")
                        .description("Параметр '" + param.getName() + "' может использоваться в regex!\n\n" +
                                   "Опасные regex:\n" +
                                   "• (a+)+ → exponential backtracking\n" +
                                   "• (a|ab)+ → polynomial time\n" +
                                   "• (.*a){x} → catastrophic backtracking\n\n" +
                                   "Атака: aaaaaaaaaaaaaaaaaaaaaaaa! → CPU 100% → DoS")
                        .endpoint(path)
                        .method(method)
                        .recommendation("ReDoS защита:\n\n" +
                                      "1. Ограничьте длину input (max 100-500 символов)\n" +
                                      "2. Timeout для regex (100ms max)\n" +
                                      "3. Избегайте nested quantifiers: (a+)+\n" +
                                      "4. Используйте regex validators (ReDoS detectors)\n" +
                                      "5. Java: Pattern.compile() с guards")
                        .owaspCategory("API4:2023 - Unrestricted Resource Consumption (ReDoS)")
                        .evidence("Regex/pattern параметр: " + param.getName())
                        .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                            Vulnerability.builder()
                                .type(VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION)
                                .severity(Severity.HIGH)
                                .build(),
                            operation, false, true))
                        .priority(2)
                        .build());
                }
            }
        }
        
        // 3. Отсутствие timeout
        if (!hasTimeout && !isConsentFlow && !isTokenEndpoint && (method.equals("POST") || method.equals("PUT"))) {
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION, path, method, null,
                    "Timeout missing"))
                .type(VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION)
                .severity(Severity.LOW)
                .title("Нет упоминания timeout")
                .description(String.format(
                    "Операция %s %s не описывает timeout. " +
                    "Долгие запросы могут блокировать ресурсы.",
                    method, path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Установите разумные timeout для операций. " +
                    "Документируйте это в спецификации."
                )
                .owaspCategory("API4:2023 - Unrestricted Resource Consumption")
                .evidence("Нет упоминания timeout в description")
                .build());
        }
        
        return vulnerabilities;
    }
    
    private boolean hasRateLimiting(Operation operation) {
        // Проверяем response 429
        if (operation.getResponses() != null && operation.getResponses().get("429") != null) {
            return true;
        }
        
        // Проверяем упоминание в description
        String text = (operation.getDescription() != null ? operation.getDescription() : "") +
                     (operation.getSummary() != null ? operation.getSummary() : "");
        String lower = text.toLowerCase();
        
        return lower.contains("rate limit") || 
               lower.contains("throttle") ||
               lower.contains("ratelimit") ||
               lower.contains("quota");
    }
    
    private boolean hasPagination(Operation operation) {
        if (operation.getParameters() == null) {
            return false;
        }
        
        for (Parameter param : operation.getParameters()) {
            String name = param.getName().toLowerCase();
            if (name.equals("limit") || name.equals("offset") || 
                name.equals("page") || name.equals("size") ||
                name.equals("per_page") || name.equals("pagesize")) {
                return true;
            }
        }
        
        return false;
    }
    
    private boolean hasTimeoutMention(Operation operation) {
        String text = (operation.getDescription() != null ? operation.getDescription() : "") +
                     (operation.getSummary() != null ? operation.getSummary() : "");
        return text.toLowerCase().contains("timeout");
    }
    
    private boolean looksLikeListEndpoint(String path) {
        // Эндпоинты типа /users, /items, /products и т.д.
        return !path.contains("{") && 
               (path.endsWith("s") || path.contains("/list") || path.contains("/all"));
    }
}

