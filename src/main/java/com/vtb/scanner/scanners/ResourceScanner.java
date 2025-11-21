package com.vtb.scanner.scanners;

import com.vtb.scanner.config.ScannerConfig;
import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.heuristics.ConfidenceCalculator;
import com.vtb.scanner.heuristics.EnhancedRules;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.semantic.ContextAnalyzer;
import com.vtb.scanner.semantic.OperationClassifier;
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

    @SuppressWarnings("unused")
    private final String targetUrl;
    private final ScannerConfig config;
    private final boolean loginRateLimitEnabled;

    private static final Set<String> RATE_LIMIT_RU_KEYWORDS = Set.of(
        "лимит запросов", "ограничение частоты", "ограничение нагрузки", "антиддос", "анти-ддоc",
        "ограничение по скорости", "квота", "квотирование", "порог частоты", "частота запросов",
        "антифрод лимит", "скорость обращений"
    );

    private static final Set<String> PAGINATION_RU_KEYWORDS = Set.of(
        "пагинация", "страница", "страницы", "размер страницы", "постранично", "курсор",
        "пачка", "батч", "ограничение выборки", "лимит записей", "постраничный вывод"
    );
    private static final Set<String> TELECOM_KEYWORDS = Set.of(
        "msisdn", "sim", "e-sim", "esim", "imsi", "iccid", "tariff", "roaming", "subscriber",
        "перенос номера", "смена тарифа", "пополнение", "баланс", "услуга связи", "трафик"
    );
    private static final Set<String> CONNECTED_VEHICLE_KEYWORDS = Set.of(
        "telematics", "connected car", "vehicle", "vin", "remote start", "door unlock", "ota",
        "лада connect", "удаленный запуск", "телематика", "управление автомобилем", "climate control"
    );

    public ResourceScanner(String targetUrl) {
        this.targetUrl = targetUrl;
        this.config = ScannerConfig.load();
        this.loginRateLimitEnabled = config.getFeatureToggles() == null
            || config.getFeatureToggles().loginRateLimitEnabled();
    }

    @Override
    public List<Vulnerability> scan(OpenAPI openAPI, OpenAPIParser parser) {
        log.debug("Запуск Resource Consumption Scanner (API4:2023)...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }

        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();

            if (pathItem == null) {
                continue;
            }

            if (pathItem.getGet() != null) {
                vulnerabilities.addAll(checkResourceLimits(path, "GET", pathItem.getGet(), openAPI, parser));
            }
            if (pathItem.getPost() != null) {
                vulnerabilities.addAll(checkResourceLimits(path, "POST", pathItem.getPost(), openAPI, parser));
            }
            if (pathItem.getPut() != null) {
                vulnerabilities.addAll(checkResourceLimits(path, "PUT", pathItem.getPut(), openAPI, parser));
            }
            if (pathItem.getDelete() != null) {
                vulnerabilities.addAll(checkResourceLimits(path, "DELETE", pathItem.getDelete(), openAPI, parser));
            }
            if (pathItem.getPatch() != null) {
                vulnerabilities.addAll(checkResourceLimits(path, "PATCH", pathItem.getPatch(), openAPI, parser));
            }
        }

        log.debug("Resource Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }

    private List<Vulnerability> checkResourceLimits(String path, String method, Operation operation,
                                                    OpenAPI openAPI, OpenAPIParser parser) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (operation == null) {
            return vulnerabilities;
        }

        OperationClassifier.OperationType opType = OperationClassifier.classify(path, method, operation);
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(path, method, operation, openAPI);

        boolean isFinancial = opType == OperationClassifier.OperationType.TRANSFER_MONEY
            || opType == OperationClassifier.OperationType.PAYMENT;
        String lowerPath = path != null ? path.toLowerCase(Locale.ROOT) : "";
        boolean isPasswordResetFlow = lowerPath.contains("password") &&
            (lowerPath.contains("reset") || lowerPath.contains("recover") || lowerPath.contains("restore"));
        boolean isLoginFlow = opType == OperationClassifier.OperationType.LOGIN
            || opType == OperationClassifier.OperationType.REGISTER
            || isPasswordResetFlow;
        boolean isConsentFlow = lowerPath.contains("consent");
        boolean isTokenEndpoint = lowerPath.contains("bank-token") || lowerPath.contains("/auth/")
            || lowerPath.contains("token");
        boolean isCatalogEndpoint = lowerPath.contains("/products") || lowerPath.contains("catalog");

        RateLimitEvidence rateLimit = detectRateLimiting(operation);
        PaginationEvidence pagination = detectPagination(operation);
        boolean hasTimeout = hasTimeoutMention(operation);
        boolean requiresAuth = parser != null && parser.requiresAuthentication(operation);

        ContextAnalyzer.APIContext apiContext =
            openAPI != null ? ContextAnalyzer.detectContext(openAPI) : ContextAnalyzer.APIContext.GENERAL;

        boolean isTelecomEndpoint = looksLikeTelecomEndpoint(lowerPath, operation);
        boolean isConnectedVehicleEndpoint = looksLikeConnectedVehicleEndpoint(lowerPath, operation);

        // 1. Отсутствие rate limiting
        if (!isConsentFlow && !isTokenEndpoint && !rateLimit.present && (isMutatingMethod(method) ||
            (method.equals("GET") && (isFinancial || isLoginFlow || isTelecomEndpoint || isConnectedVehicleEndpoint)))) {

            Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
            Severity severity = determineRateLimitSeverity(baseSeverity, isFinancial || isTelecomEndpoint || isConnectedVehicleEndpoint,
                isLoginFlow, requiresAuth, apiContext);

            Vulnerability tempVuln = Vulnerability.builder()
                .type(VulnerabilityType.RATE_LIMIT_MISSING)
                .severity(severity)
                .build();

            int confidence = ConfidenceCalculator.calculateConfidence(tempVuln, operation, false, false);
            int priority = ConfidenceCalculator.calculatePriority(tempVuln, confidence);

            StringBuilder description = new StringBuilder()
                .append(String.format("Эндпоинт %s %s не описывает механизм rate limiting. ", method, path))
                .append("Возможна перегрузка системы множественными запросами. ");

            if (!rateLimit.partialSignals.isEmpty()) {
                description.append("Обнаружены косвенные признаки, но они недостаточны: ")
                    .append(String.join(", ", rateLimit.partialSignals))
                    .append(". ");
            } else {
                description.append("Не найдены заголовки X-RateLimit-*, HTTP 429 или Retry-After.");
            }

            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.RATE_LIMIT_MISSING, path, method, null,
                    "Rate limiting missing"))
                .type(VulnerabilityType.RATE_LIMIT_MISSING)
                .severity(severity)
                .title("Отсутствует rate limiting")
                .confidence(confidence)
                .priority(priority)
                .impactLevel(resolveRateLimitImpact(isFinancial, isLoginFlow, isTelecomEndpoint, isConnectedVehicleEndpoint, apiContext))
                .description(description.toString().trim())
                .endpoint(path)
                .method(method)
                .recommendation(buildRateLimitRecommendation(isLoginFlow, apiContext))
                .owaspCategory("API4:2023 - Unrestricted Resource Consumption")
                .evidence(rateLimitEvidenceText(rateLimit))
                .riskScore(riskScore)
                .build());
        }

        // 2. GET без пагинации
        if ("GET".equals(method) && !pagination.present && !isCatalogEndpoint && looksLikeListEndpoint(path)) {
            Vulnerability tempVuln = Vulnerability.builder()
                .type(VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION)
                .severity(Severity.MEDIUM)
                .build();

            int confidence = ConfidenceCalculator.calculateConfidence(tempVuln, operation, false, false);
            int priority = ConfidenceCalculator.calculatePriority(tempVuln, confidence);

            String description = String.format(
                "Эндпоинт %s возвращает список без ограничений. Может вернуть миллионы записей → DoS.", path);
            if (!pagination.partialSignals.isEmpty()) {
                description += " Косвенные признаки пагинации: " + String.join(", ", pagination.partialSignals) + ".";
            }

            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION, path, method, null,
                    "Pagination missing"))
                .type(VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION)
                .severity(adjustPaginationSeverity(apiContext, isFinancial, isTelecomEndpoint, isConnectedVehicleEndpoint))
                .title("Отсутствует пагинация")
                .description(description)
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Добавьте пагинацию: параметры limit/offset, page/size или cursor. " +
                    "Установите разумный лимит по умолчанию (например, 100). " +
                    "Документируйте заголовки X-Total-Count и ссылки next/prev."
                )
                .owaspCategory("API4:2023 - Unrestricted Resource Consumption")
                .evidence("Нет параметров ограничения выборки (limit, page, offset, cursor)")
                .impactLevel(resolvePaginationImpact(isFinancial, isTelecomEndpoint, isConnectedVehicleEndpoint, apiContext))
                .confidence(confidence)
                .priority(priority)
                .riskScore(riskScore)
                .build());
        }

        // НОВЫЕ ПРОВЕРКИ: Path Traversal, NoSQL, Template Injection
        if (operation.getParameters() != null) {
            for (Parameter param : operation.getParameters()) {
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
                        .confidence(ConfidenceCalculator.calculateConfidence(
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
                        .confidence(ConfidenceCalculator.calculateConfidence(
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
                        .confidence(ConfidenceCalculator.calculateConfidence(
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
                        .confidence(ConfidenceCalculator.calculateConfidence(
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
                        .confidence(ConfidenceCalculator.calculateConfidence(
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
                        .confidence(ConfidenceCalculator.calculateConfidence(
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
        if (!hasTimeout && !isConsentFlow && !isTokenEndpoint &&
            (method.equals("POST") || method.equals("PUT") || method.equals("PATCH") ||
             (method.equals("GET") && (isFinancial || isTelecomEndpoint || isConnectedVehicleEndpoint || mentionsLongProcessing(operation))))) {
            Vulnerability tempVuln = Vulnerability.builder()
                .type(VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION)
                .severity(Severity.LOW)
                .build();

            int confidence = ConfidenceCalculator.calculateConfidence(tempVuln, operation, false, false);
            int priority = ConfidenceCalculator.calculatePriority(tempVuln, confidence);
            Severity severity = adjustTimeoutSeverity(apiContext, mentionsLongProcessing(operation), isLoginFlow);

            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION, path, method, null,
                    "Timeout missing"))
                .type(VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION)
                .severity(severity)
                .title("Нет упоминания timeout")
                .description(String.format(
                    "Операция %s %s не описывает timeout. " +
                    "Долгие запросы могут блокировать сервис, особенно при обработке длительных операций.",
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
                .impactLevel(timeoutImpact(apiContext, mentionsLongProcessing(operation), isTelecomEndpoint, isConnectedVehicleEndpoint))
                .confidence(confidence)
                .priority(priority)
                .riskScore(riskScore)
                .build());
        }
        
        return vulnerabilities;
    }
    
    private RateLimitEvidence detectRateLimiting(Operation operation) {
        RateLimitEvidence evidence = new RateLimitEvidence();
        if (operation == null) {
            return evidence;
        }

        if (operation.getResponses() != null) {
            operation.getResponses().forEach((code, response) -> {
                if (response == null) {
                    return;
                }
                if ("429".equals(code)) {
                    evidence.present = true;
                    evidence.positiveSignals.add("HTTP 429 Too Many Requests");
                }
                if (response.getHeaders() != null) {
                    response.getHeaders().forEach((headerName, header) -> {
                        String lower = headerName.toLowerCase(Locale.ROOT);
                        if (lower.startsWith("x-ratelimit") || lower.equals("retry-after")) {
                            evidence.present = true;
                            evidence.positiveSignals.add("Header " + headerName);
                        } else if (lower.contains("limit") || lower.contains("burst")) {
                            evidence.partialSignals.add("Header " + headerName);
                        }
                        if (header != null && header.getDescription() != null &&
                            header.getDescription().toLowerCase(Locale.ROOT).contains("rate")) {
                            evidence.partialSignals.add("Header description указывает на лимиты: " + headerName);
                        }
                    });
                }
                if (response.getLinks() != null && !response.getLinks().isEmpty()) {
                    response.getLinks().forEach((linkName, link) -> {
                        if (linkName != null && linkName.toLowerCase(Locale.ROOT).contains("throttle")) {
                            evidence.partialSignals.add("Response link " + linkName);
                        }
                    });
                }
            });
        }

        String description = ((operation.getDescription() != null ? operation.getDescription() : "") +
            (operation.getSummary() != null ? operation.getSummary() : "")).toLowerCase(Locale.ROOT);

        if (description.contains("rate limit") || description.contains("throttle") ||
            description.contains("quota") || description.contains("burst") ||
            RATE_LIMIT_RU_KEYWORDS.stream().anyMatch(description::contains)) {
            evidence.present = true;
            evidence.positiveSignals.add("Описание содержит rate-limit/quotа");
        }
        if (description.contains("retry-after") || description.contains("backoff") ||
            description.contains("exponential backoff") ||
            description.contains("повтор") || description.contains("ожидание перед повтором")) {
            evidence.partialSignals.add("Сценарий retry/backoff описан");
        }

        if (operation.getParameters() != null) {
            for (Parameter parameter : operation.getParameters()) {
                if (parameter == null || parameter.getName() == null) {
                    continue;
                }
                String name = parameter.getName().toLowerCase(Locale.ROOT);
                if (name.startsWith("x-ratelimit") || name.startsWith("ratelimit-") ||
                    name.equals("retry-after")) {
                    evidence.present = true;
                    evidence.positiveSignals.add("Заголовок " + parameter.getName());
                } else if (name.contains("limit") || name.contains("max-requests") || name.contains("threshold") ||
                    name.contains("frequency") || name.contains("burst") || name.contains("quota") ||
                    name.contains("огранич") || name.contains("лимит") || name.contains("квот")) {
                    evidence.partialSignals.add("Параметр " + parameter.getName());
                }
            }
        }

        if (operation.getExtensions() != null) {
            operation.getExtensions().forEach((key, value) -> {
                String lower = key.toLowerCase(Locale.ROOT);
                if (lower.contains("rate") || lower.contains("quota")) {
                    evidence.present = true;
                    evidence.positiveSignals.add("Extension " + key);
                }
            });
        }

        return evidence;
    }

    private PaginationEvidence detectPagination(Operation operation) {
        PaginationEvidence evidence = new PaginationEvidence();
        if (operation == null) {
            return evidence;
        }

        if (operation.getParameters() != null) {
            for (Parameter param : operation.getParameters()) {
                if (param == null || param.getName() == null) {
                    continue;
                }
                String lowerName = param.getName().toLowerCase(Locale.ROOT);
                if (isPaginationParameter(lowerName) ||
                    PAGINATION_RU_KEYWORDS.stream().anyMatch(lowerName::contains)) {
                    evidence.present = true;
                    evidence.positiveSignals.add("Параметр " + param.getName());
                } else if (lowerName.contains("batch") || lowerName.contains("chunk") ||
                    lowerName.contains("page") || lowerName.contains("limit") ||
                    lowerName.contains("огранич") || lowerName.contains("пачк") || lowerName.contains("страниц")) {
                    evidence.partialSignals.add("Параметр " + param.getName());
                }
            }
        }

        if (operation.getResponses() != null) {
            for (String code : Arrays.asList("200", "206")) {
                var response = operation.getResponses().get(code);
                if (response == null) {
                    continue;
                }
                if (response.getHeaders() != null) {
                    response.getHeaders().forEach((headerName, header) -> {
                        String lower = headerName.toLowerCase(Locale.ROOT);
                        if (lower.startsWith("x-next") || lower.contains("cursor") || lower.contains("continuation")
                            || lower.contains("page-size") || lower.contains("page-count")) {
                            evidence.present = true;
                            evidence.positiveSignals.add("Header " + headerName);
                        }
                    });
                }
                if (response.getLinks() != null && !response.getLinks().isEmpty()) {
                    evidence.present = true;
                    evidence.positiveSignals.add("Response Links: " + response.getLinks().keySet());
                }
            }
        }

        String description = ((operation.getDescription() != null ? operation.getDescription() : "") +
            (operation.getSummary() != null ? operation.getSummary() : "")).toLowerCase(Locale.ROOT);
        if (description.contains("pagination") || description.contains("page size") ||
            description.contains("cursor") || description.contains("batch size") ||
            description.contains("pageable") ||
            PAGINATION_RU_KEYWORDS.stream().anyMatch(description::contains)) {
            evidence.partialSignals.add("Описание упоминает пагинацию/лимиты");
        }

        return evidence;
    }

    private boolean isPaginationParameter(String name) {
        return name.equals("limit") || name.equals("offset") || name.equals("page") ||
            name.equals("size") || name.equals("per_page") || name.equals("pagesize") ||
            name.equals("page_size") || name.equals("page-number") || name.equals("page_number") ||
            name.equals("pageindex") || name.equals("page_index") || name.equals("cursor") ||
            name.equals("next_token") || name.equals("continuationtoken") ||
            name.equals("continuation_token") || name.equals("page_token") || name.equals("pagetoken") ||
            name.equals("nexttoken") || name.equals("start_after") || name.equals("end_before") ||
            name.equals("стр") || name.equals("страница") || name.equals("размер_страницы") ||
            name.equals("лимит") || name.equals("ограничение");
    }

    private static class RateLimitEvidence {
        boolean present;
        List<String> positiveSignals = new ArrayList<>();
        List<String> partialSignals = new ArrayList<>();
    }

    private static class PaginationEvidence {
        boolean present;
        List<String> positiveSignals = new ArrayList<>();
        List<String> partialSignals = new ArrayList<>();
    }
    
    private boolean hasTimeoutMention(Operation operation) {
        String text = (operation.getDescription() != null ? operation.getDescription() : "") +
                     (operation.getSummary() != null ? operation.getSummary() : "");
        return text.toLowerCase().contains("timeout");
    }

    private boolean mentionsLongProcessing(Operation operation) {
        if (operation == null) {
            return false;
        }
        String text = ((operation.getDescription() != null ? operation.getDescription() : "") +
            (operation.getSummary() != null ? operation.getSummary() : "")).toLowerCase(Locale.ROOT);
        return text.contains("long") || text.contains("batch") || text.contains("export") ||
               text.contains("report") || text.contains("bulk") || text.contains("async");
    }
    
    private boolean looksLikeListEndpoint(String path) {
        if (path == null) {
            return false;
        }
        String lower = path.toLowerCase(Locale.ROOT);
        return !lower.contains("{") &&
               (lower.endsWith("s") || lower.contains("/list") || lower.contains("/all") || lower.contains("/search"));
    }

    private boolean isMutatingMethod(String method) {
        return "POST".equals(method) || "PUT".equals(method) || "DELETE".equals(method) || "PATCH".equals(method);
    }

    private Severity determineRateLimitSeverity(Severity baseSeverity, boolean isFinancial, boolean isLoginFlow,
                                                boolean requiresAuth, ContextAnalyzer.APIContext apiContext) {
        Severity severity = baseSeverity.compareTo(Severity.MEDIUM) < 0 ? Severity.MEDIUM : baseSeverity;

        if (isFinancial || apiContext == ContextAnalyzer.APIContext.BANKING) {
            severity = Severity.CRITICAL;
        } else if (isLoginFlow && loginRateLimitEnabled) {
            severity = Severity.HIGH;
        }

        if (requiresAuth && severity == Severity.CRITICAL) {
            severity = Severity.HIGH;
        }

        return severity;
    }

    private Severity adjustPaginationSeverity(ContextAnalyzer.APIContext apiContext,
                                              boolean isFinancial,
                                              boolean isTelecom,
                                              boolean isConnectedVehicle) {
        if (isFinancial || isTelecom || isConnectedVehicle || apiContext == ContextAnalyzer.APIContext.BANKING) {
            return Severity.HIGH;
        }
        if (apiContext == ContextAnalyzer.APIContext.GOVERNMENT ||
            apiContext == ContextAnalyzer.APIContext.TELECOM ||
            apiContext == ContextAnalyzer.APIContext.AUTOMOTIVE) {
            return Severity.HIGH;
        }
        return Severity.MEDIUM;
    }

    private Severity adjustTimeoutSeverity(ContextAnalyzer.APIContext apiContext, boolean highRiskOperation,
                                           boolean isLoginFlow) {
        if (highRiskOperation) {
            return Severity.MEDIUM;
        }
        if (apiContext == ContextAnalyzer.APIContext.GOVERNMENT ||
            apiContext == ContextAnalyzer.APIContext.HEALTHCARE ||
            apiContext == ContextAnalyzer.APIContext.TELECOM ||
            apiContext == ContextAnalyzer.APIContext.AUTOMOTIVE) {
            return Severity.MEDIUM;
        }
        if (isLoginFlow) {
            return Severity.MEDIUM;
        }
        return Severity.LOW;
    }

    private String resolveRateLimitImpact(boolean isFinancial,
                                          boolean isLoginFlow,
                                          boolean isTelecom,
                                          boolean isConnectedVehicle,
                                          ContextAnalyzer.APIContext apiContext) {
        if (isFinancial) {
            return "FINANCIAL_FRAUD: Массовое списание средств";
        }
        if (isTelecom || apiContext == ContextAnalyzer.APIContext.TELECOM) {
            return "TELECOM_OUTAGE: Массовое подключение услуг/перехват msisdn";
        }
        if (isConnectedVehicle || apiContext == ContextAnalyzer.APIContext.AUTOMOTIVE) {
            return "SAFETY_RISK: Массовое управление транспортом";
        }
        if (apiContext == ContextAnalyzer.APIContext.GOVERNMENT) {
            return "SERVICE_OUTAGE: Нарушение предоставления госуслуг";
        }
        if (isLoginFlow) {
            return "ACCOUNT_LOCKOUT: Брутфорс/credential stuffing";
        }
        return "DOS_RISK: Перегрузка ресурса";
    }

    private String buildRateLimitRecommendation(boolean isLoginFlow, ContextAnalyzer.APIContext apiContext) {
        String base = "Реализуйте rate limiting (например, 100 requests/minute) и backoff. " +
            "Возвращайте HTTP 429 Too Many Requests и заголовки X-RateLimit-Limit, X-RateLimit-Remaining.";
        if (isLoginFlow) {
            base += " Для login/OTP реализуйте captcha/lockout после нескольких попыток.";
        }
        if (apiContext == ContextAnalyzer.APIContext.BANKING) {
            base += " Для финансовых операций используйте динамические лимиты и мониторинг аномалий.";
        }
        return base;
    }

    private String rateLimitEvidenceText(RateLimitEvidence evidence) {
        if (!evidence.positiveSignals.isEmpty()) {
            return String.join(", ", evidence.positiveSignals);
        }
        if (!evidence.partialSignals.isEmpty()) {
            return "Косвенные признаки: " + String.join(", ", evidence.partialSignals);
        }
        return "Не обнаружены X-RateLimit заголовки, HTTP 429, Retry-After.";
    }

    private String timeoutImpact(ContextAnalyzer.APIContext apiContext, boolean mentionsLongProcessing,
                                 boolean isTelecom, boolean isConnectedVehicle) {
        if (mentionsLongProcessing) {
            return "RESOURCE_LOCK: Долгие операции без таймаута";
        }
        if (isTelecom || apiContext == ContextAnalyzer.APIContext.TELECOM) {
            return "TELECOM_OUTAGE: Длительные операции блокируют биллинг";
        }
        if (isConnectedVehicle || apiContext == ContextAnalyzer.APIContext.AUTOMOTIVE) {
            return "SAFETY_RISK: Повисшие команды управления транспортом";
        }
        if (apiContext == ContextAnalyzer.APIContext.HEALTHCARE || apiContext == ContextAnalyzer.APIContext.GOVERNMENT) {
            return "SERVICE_DEGRADATION: Риск задержек в критичных сервисах";
        }
        return "DOS_RISK: Потенциальное удержание соединений";
    }

    private String resolvePaginationImpact(boolean isFinancial,
                                           boolean isTelecom,
                                           boolean isConnectedVehicle,
                                           ContextAnalyzer.APIContext apiContext) {
        if (isFinancial) {
            return "DATA_EXFILTRATION: Массовая выгрузка транзакций";
        }
        if (isTelecom || apiContext == ContextAnalyzer.APIContext.TELECOM) {
            return "TELECOM_OUTAGE: Массовый сбор данных абонентов";
        }
        if (isConnectedVehicle || apiContext == ContextAnalyzer.APIContext.AUTOMOTIVE) {
            return "SAFETY_RISK: Массовое извлечение телематики";
        }
        return "DOS_RISK: Нерациональная загрузка";
    }

    private boolean looksLikeTelecomEndpoint(String path, Operation operation) {
        String text = (path != null ? path : "") + " " + combinedOperationText(operation);
        String lower = text.toLowerCase(Locale.ROOT);
        return TELECOM_KEYWORDS.stream().anyMatch(lower::contains);
    }

    private boolean looksLikeConnectedVehicleEndpoint(String path, Operation operation) {
        String text = (path != null ? path : "") + " " + combinedOperationText(operation);
        String lower = text.toLowerCase(Locale.ROOT);
        return CONNECTED_VEHICLE_KEYWORDS.stream().anyMatch(lower::contains);
    }

    private String combinedOperationText(Operation operation) {
        if (operation == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        if (operation.getSummary() != null) {
            sb.append(operation.getSummary()).append(' ');
        }
        if (operation.getDescription() != null) {
            sb.append(operation.getDescription()).append(' ');
        }
        return sb.toString().toLowerCase(Locale.ROOT);
    }
}

