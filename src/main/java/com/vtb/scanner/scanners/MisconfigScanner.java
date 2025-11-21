package com.vtb.scanner.scanners;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.deep.*;
import com.vtb.scanner.heuristics.ConfidenceCalculator;
import com.vtb.scanner.heuristics.EnhancedRules;
import com.vtb.scanner.heuristics.SmartAnalyzer;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.models.VulnerabilityIdGenerator;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.examples.Example;
import io.swagger.v3.oas.models.headers.Header;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.servers.Server;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.Optional;
import java.util.stream.Stream;
import java.util.regex.Pattern;

import com.vtb.scanner.util.AccessControlHeuristics;
import com.vtb.scanner.semantic.ContextAnalyzer;

/**
 * API8:2023 - Security Misconfiguration
 * Проверяет проблемы конфигурации: HTTP, CORS, verbose errors
 */
@Slf4j
public class MisconfigScanner implements VulnerabilityScanner {
    
    @SuppressWarnings("unused")
    private final String targetUrl;
    private static final List<String> STACK_TRACE_TOKENS = List.of(
        "stack trace", "stacktrace", "traceback", "caused by", "java.lang.", "exception in thread",
        "nullpointerexception", "illegalargumentexception", "org.springframework", "org.hibernate"
    );
    private static final List<String> DEBUG_TOKENS = List.of(
        "debug", "detailed error", "internal error id", "trace id", "correlation id",
        "full message", "detailed message", "developer message", "diagnostic", "errorreference"
    );
    private static final List<String> SQL_TOKENS = List.of(
        "sqlstate", "constraint violation", "syntax error", "database error", "psqlexception",
        "mysql", "postgres", "select ", "insert into", "update ", "delete from"
    );
    private static final List<String> TECHNOLOGY_TOKENS = List.of(
        "spring boot", "hibernate", "tomcat", "jetty", "weblogic", "jboss", "asp.net", "django",
        "laravel", "rails", "expressjs", "node.js", "graphql error", "kotlin"
    );
    private static final Set<String> SENSITIVE_CORS_HEADERS = Set.of(
        "*", "authorization", "cookie", "cookies", "x-api-key", "x-auth-token", "api-key", "set-cookie"
    );
    private static final Set<String> SENSITIVE_EXPOSE_HEADERS = Set.of(
        "*", "authorization", "set-cookie", "cookie", "x-api-key", "x-auth-token"
    );
    private static final Set<String> DANGEROUS_ORIGIN_VALUES = Set.of("null");
    private static final List<String> DANGEROUS_ORIGIN_PREFIXES = List.of(
        "file://", "chrome-extension://", "moz-extension://", "capacitor://", "ionic://", "ms-appx://"
    );
    private static final Set<String> LOOPBACK_HOSTS = Set.of("localhost", "127.0.0.1", "127.0.1.1", "::1");
    private static final Pattern PRIVATE_IPV4_PATTERN = Pattern.compile(
        "^(10(?:\\.\\d{1,3}){3}|192\\.168(?:\\.\\d{1,3}){2}|172\\.(1[6-9]|2\\d|3[0-1])(?:\\.\\d{1,3}){2})$"
    );
    private static final Pattern PRIVATE_IPV6_PATTERN = Pattern.compile("^(fd[0-9a-f]{0,2}|fe80):.*",
        Pattern.CASE_INSENSITIVE);
    private static final EnumSet<ContextAnalyzer.APIContext> HIGH_RISK_CONTEXTS =
        EnumSet.of(
            ContextAnalyzer.APIContext.BANKING,
            ContextAnalyzer.APIContext.GOVERNMENT,
            ContextAnalyzer.APIContext.HEALTHCARE,
            ContextAnalyzer.APIContext.TELECOM,
            ContextAnalyzer.APIContext.AUTOMOTIVE
        );
    private static final String IMPACT_DATA_EXFILTRATION = "CRITICAL:Cross-Origin Data Exfiltration";
    private static final String IMPACT_UNSAFE_ORIGIN = "HIGH:Unsafe Cross-Origin Policy";
    private static final String IMPACT_TOKEN_LEAK = "HIGH:Token Exposure via CORS";
    private static final String IMPACT_CREDENTIALS_MISALIGN = "CRITICAL:Cross-Origin Credential Abuse";
    private static final String IMPACT_METHOD_WILDCARD = "MEDIUM:Overly Permissive CORS Methods";
    private static final String IMPACT_PRIVATE_NETWORK = "CRITICAL:Private Network Exposure";
    private static final String IMPACT_DANGEROUS_ORIGIN = "HIGH:Null/File Origin Abuse";
    private static final String IMPACT_DEV_ORIGIN = "MEDIUM:Development Origin in Production";
    
    public MisconfigScanner(String targetUrl) {
        this.targetUrl = targetUrl;
    }
    
    @Override
    public List<Vulnerability> scan(OpenAPI openAPI, OpenAPIParser parser) {
        log.info("Запуск Misconfiguration Scanner (API8:2023)...");
        log.info("🔬 С ГЛУБОКИМИ проверками: Headers, Cookies, OAuth, JWT, File Uploads!");
        
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null) {
            return vulnerabilities;
        }
        
        // КОНТЕКСТ: определяем тип API для адаптации severity
        ContextAnalyzer.APIContext context = 
            ContextAnalyzer.detectContext(openAPI);
        
        // 1. Проверка HTTP vs HTTPS
        vulnerabilities.addAll(checkTransportSecurity(openAPI));
        
        // 2. Проверка CORS
        vulnerabilities.addAll(checkCORS(openAPI, parser, context));
        
        // 3. Проверка verbose errors
        vulnerabilities.addAll(checkErrorHandling(openAPI, context));
        
        // 4. НОВОЕ: Security Headers (HSTS, CSP, X-Frame, etc.)
        vulnerabilities.addAll(SecurityHeadersChecker.checkSecurityHeaders(openAPI, parser, context));
        
        // 5. НОВОЕ: Cookie Security (HttpOnly, Secure, SameSite)
        vulnerabilities.addAll(CookieSecurityChecker.checkCookies(openAPI, context));
        
        // 6. НОВОЕ: OAuth 2.0 Flows
        vulnerabilities.addAll(OAuthFlowChecker.checkOAuthFlows(openAPI, context));
        
        // 7. НОВОЕ: JWT токены
        vulnerabilities.addAll(JWTAnalyzer.analyzeJWT(openAPI, context));
        
        // 8. НОВОЕ: File Uploads
        vulnerabilities.addAll(FileUploadChecker.checkFileUploads(openAPI, context));
        
        // 9. НОВЕЙШЕЕ: GraphQL Security
        vulnerabilities.addAll(checkGraphQL(openAPI, parser));
        
        // 9.1 gRPC Security
        vulnerabilities.addAll(checkGrpc(openAPI, parser));
        
        // 9.2 WebSocket Hardening
        vulnerabilities.addAll(checkWebSockets(openAPI, parser));
        
        // 10. НОВЕЙШЕЕ: IoT/Device Management
        vulnerabilities.addAll(checkIoT(openAPI, parser));
        
        // 11. НОВЕЙШЕЕ: Open Banking/PSD2
        vulnerabilities.addAll(checkOpenBanking(openAPI, parser));
        
        log.info("Misconfiguration Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkTransportSecurity(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getServers() == null || openAPI.getServers().isEmpty()) {
            return vulnerabilities;
        }
        
        // Определяем контекст для адаптации severity
        ContextAnalyzer.APIContext context = 
            ContextAnalyzer.detectContext(openAPI);
        
        for (Server server : openAPI.getServers()) {
            if (server.getUrl() != null && server.getUrl().startsWith("http://")) {
                // КОНТЕКСТ: для банков/госструктур HTTP = CRITICAL!
                boolean strongAccess = hasGlobalStrongAuthorization(openAPI);
                boolean consentContext = hasGlobalConsentEvidence(openAPI);
                Severity severity = determineHttpSeverity(context, strongAccess, consentContext);
                int riskScore = calculateHttpRiskScore(severity, strongAccess, consentContext);
                
                Vulnerability tempVuln = Vulnerability.builder()
                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                    .severity(severity)
                    .build();
                
                vulnerabilities.add(Vulnerability.builder()
                    .id("MISC-HTTP")
                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                    .severity(severity)
                    .riskScore(riskScore)
                    .confidence(ConfidenceCalculator.calculateConfidence(
                        tempVuln, null, false, true)) // evidence=true (точно HTTP)
                    .priority(ConfidenceCalculator.calculatePriority(
                        tempVuln, 100))
                    .title("Использование незащищенного HTTP")
                    .description(String.format(
                        "Server URL использует HTTP вместо HTTPS: %s. " +
                        "Данные передаются в открытом виде, возможен перехват (MITM).",
                        server.getUrl()
                    ))
                    .endpoint(server.getUrl() != null ? "server:" + server.getUrl() : "server:unknown")
                    .method("CONFIG")
                    .recommendation(
                        "Используйте HTTPS для всех API. " +
                        "Настройте TLS 1.2+ с современными cipher suites. " +
                        "Для России: поддержка ГОСТ TLS."
                    )
                    .owaspCategory("API8:2023 - Security Misconfiguration")
                    .evidence(buildHttpEvidence(server.getUrl(), riskScore, strongAccess, consentContext))
                    .build());
            }
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkGrpc(OpenAPI openAPI, OpenAPIParser parser) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            String pathLower = path != null ? path.toLowerCase(Locale.ROOT) : "";
            
            Map<String, Operation> operations = getOperationsWithMethods(pathItem);
            for (Map.Entry<String, Operation> opEntry : operations.entrySet()) {
                String method = opEntry.getKey();
                Operation op = opEntry.getValue();
                if (op == null) {
                    continue;
                }
                
                Set<String> samples = collectOperationSamples(op);
                if (!looksLikeGrpcEndpoint(pathLower, samples, op)) {
                    continue;
                }
                
                List<String> serverUrls = resolveServerUrls(openAPI, pathItem, op);
                boolean hasSecureTransport = serverUrls.stream().anyMatch(this::isSecureGrpcUrl);
                boolean hasInsecureTransport = serverUrls.stream().anyMatch(this::isInsecureGrpcUrl);
                
                int riskScore = SmartAnalyzer.calculateRiskScore(path, method, op, openAPI);
                Severity baseSeverity = SmartAnalyzer.severityFromRiskScore(riskScore);
                
                boolean requiresAuth = parser != null && parser.requiresAuthentication(op);
                boolean hasAccessControl = AccessControlHeuristics.hasExplicitAccessControl(op, path, openAPI);
                
                if (!requiresAuth && !hasAccessControl) {
                    Severity severity = Severity.CRITICAL;
                    Vulnerability temp = Vulnerability.builder()
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .build();
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, null,
                            "gRPC метод без аутентификации"))
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .title("gRPC метод доступен без аутентификации")
                        .description("gRPC операция " + method + " " + path + " не описывает обязательной аутентификации. " +
                            "Это позволяет вызывать удалённые процедуры без токена или сертификата клиента.")
                        .endpoint(path)
                        .method(method)
                        .recommendation("Добавьте mTLS/Token security для gRPC. Опишите securitySchemes, scopes и " +
                            "проверку сервисов-потребителей.")
                        .owaspCategory("API8:2023 - Security Misconfiguration (gRPC)")
                        .evidence("gRPC индикаторы: " + String.join(", ", new ArrayList<>(samples)))
                        .confidence(ConfidenceCalculator.calculateConfidence(temp, op, false, true))
                        .priority(ConfidenceCalculator.calculatePriority(
                            temp,
                            ConfidenceCalculator.calculateConfidence(temp, op, false, true)))
                        .build());
                }
                
                if (hasInsecureTransport && !hasSecureTransport) {
                    Severity severity = baseSeverity.compareTo(Severity.HIGH) >= 0 ? Severity.CRITICAL : Severity.HIGH;
                    Vulnerability temp = Vulnerability.builder()
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .build();
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, null,
                            "gRPC без TLS"))
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .title("gRPC транспорт без TLS/h2")
                        .description("gRPC endpoint " + method + " " + path + " объявлен на небезопасном транспорте (plaintext). " +
                            "Это упрощает MitM, downgrades и перехват RPC трафика.")
                        .endpoint(path)
                        .method(method)
                        .recommendation("Переключите сервис на grpcs:// (TLS + HTTP/2), запретите plaintext режимы и " +
                            "проверьте ALPN/сертификаты.")
                        .owaspCategory("API8:2023 - Security Misconfiguration (gRPC Transport)")
                        .evidence(serverUrls.isEmpty() ? "Server URLs не указаны" : "Server URLs: " + String.join(", ", serverUrls))
                        .confidence(ConfidenceCalculator.calculateConfidence(temp, op, false, true))
                        .priority(ConfidenceCalculator.calculatePriority(
                            temp,
                            ConfidenceCalculator.calculateConfidence(temp, op, false, true)))
                        .build());
                }
            }
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkWebSockets(OpenAPI openAPI, OpenAPIParser parser) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            String pathLower = path != null ? path.toLowerCase(Locale.ROOT) : "";
            
            Map<String, Operation> operations = getOperationsWithMethods(pathItem);
            for (Map.Entry<String, Operation> opEntry : operations.entrySet()) {
                String method = opEntry.getKey();
                Operation op = opEntry.getValue();
                if (op == null) {
                    continue;
                }
                
                Set<String> samples = collectOperationSamples(op);
                if (!looksLikeWebSocketEndpoint(pathLower, samples, op)) {
                    continue;
                }
                
                List<String> serverUrls = resolveServerUrls(openAPI, pathItem, op);
                boolean hasSecureTransport = serverUrls.stream().anyMatch(this::isSecureWebSocketUrl);
                boolean hasInsecureTransport = serverUrls.stream().anyMatch(this::isInsecureWebSocketUrl);
                
                int riskScore = SmartAnalyzer.calculateRiskScore(path, method, op, openAPI);
                Severity baseSeverity = SmartAnalyzer.severityFromRiskScore(riskScore);
                
                boolean requiresAuth = parser != null && parser.requiresAuthentication(op);
                boolean hasAccessControl = AccessControlHeuristics.hasExplicitAccessControl(op, path, openAPI);
                
                if (!requiresAuth && !hasAccessControl) {
                    Severity severity = baseSeverity.compareTo(Severity.HIGH) >= 0 ? Severity.HIGH : Severity.MEDIUM;
                    Vulnerability temp = Vulnerability.builder()
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .build();
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, null,
                            "WebSocket без авторизации"))
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .title("WebSocket handshake без авторизации")
                        .description("WebSocket endpoint " + method + " " + path + " не описывает токены/заголовки авторизации. " +
                            "Анонимный клиент может установить постоянное соединение для Data Exfiltration или DoS.")
                        .endpoint(path)
                        .method(method)
                        .recommendation("Передавайте токены (Bearer/HMAC) в headers/query, проверяйте Origin, внедрите rate limiting " +
                            "и закрытие соединения при отсутствии авторизации.")
                        .owaspCategory("API8:2023 - Security Misconfiguration (WebSocket)")
                        .evidence("WebSocket индикаторы: " + String.join(", ", new ArrayList<>(samples)))
                        .confidence(ConfidenceCalculator.calculateConfidence(temp, op, false, true))
                        .priority(ConfidenceCalculator.calculatePriority(
                            temp,
                            ConfidenceCalculator.calculateConfidence(temp, op, false, true)))
                        .build());
                }
                
                if (hasInsecureTransport && !hasSecureTransport) {
                    Severity severity = Severity.CRITICAL;
                    Vulnerability temp = Vulnerability.builder()
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .build();
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, null,
                            "WebSocket без WSS"))
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .title("WebSocket использует небезопасный ws:// транспорт")
                        .description("WebSocket endpoint " + method + " " + path + " объявлен по ws://. " +
                            "Без TLS handshake и payload доступны для чтения/изменения (MitM).")
                        .endpoint(path)
                        .method(method)
                        .recommendation("Используйте только wss:// (TLS). Включите HSTS, ограничьте список Origin и " +
                            "выполняйте проверку сертификатов.")
                        .owaspCategory("API8:2023 - Security Misconfiguration (WebSocket Transport)")
                        .evidence(serverUrls.isEmpty() ? "Server URLs не указаны" : "Server URLs: " + String.join(", ", serverUrls))
                        .confidence(ConfidenceCalculator.calculateConfidence(temp, op, false, true))
                        .priority(ConfidenceCalculator.calculatePriority(
                            temp,
                            ConfidenceCalculator.calculateConfidence(temp, op, false, true)))
                        .build());
                }
            }
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkCORS(OpenAPI openAPI,
                                         OpenAPIParser parser,
                                         ContextAnalyzer.APIContext context) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        Set<String> reportedKeys = new HashSet<>();
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            Map<String, Operation> operations = getOperationsWithMethods(pathItem);
            for (Map.Entry<String, Operation> opEntry : operations.entrySet()) {
                String method = opEntry.getKey();
                Operation operation = opEntry.getValue();
                if (operation == null || operation.getResponses() == null) {
                    continue;
                }

                int riskScore = SmartAnalyzer.calculateRiskScore(path, method, operation, openAPI);

                boolean documentedCors = hasCorsDocumentation(operation);
                boolean hasCorsHeaders = false;

                for (Map.Entry<String, ApiResponse> responseEntry : operation.getResponses().entrySet()) {
                    ApiResponse response = resolveApiResponse(responseEntry.getValue(), openAPI);
                    if (response == null) {
                        continue;
                    }
                    CorsEvidence evidence = extractCorsHeaders(response);
                    if (!evidence.isEmpty()) {
                        hasCorsHeaders = true;
                    }
                    if (evidence.wildcardAndCredentials) {
                        Severity severity = isHighRiskContext(context) ? Severity.CRITICAL : Severity.HIGH;
                        severity = applyContextSeverity(severity, context);
                        if (requiresAuth(parser, operation)) {
                            severity = elevateSeverity(severity);
                        }
                        addCorsVulnerability(vulnerabilities, reportedKeys, path, method, operation,
                            riskScore,
                            "Небезопасная CORS политика (credentials + *)",
                            String.format("Эндпоинт %s %s возвращает Access-Control-Allow-Origin: * одновременно с Allow-Credentials=true. " +
                                "Злоумышленник может выполнять запросы из любого происхождения и получать чувствительные данные.", method, path),
                            evidence, severity, IMPACT_DATA_EXFILTRATION, null);
                    } else if (evidence.wildcardOrigin) {
                        Severity severity = isHighRiskContext(context) ? Severity.HIGH : Severity.MEDIUM;
                        severity = applyContextSeverity(severity, context);
                        if (requiresAuth(parser, operation)) {
                            severity = elevateSeverity(severity);
                        }
                        addCorsVulnerability(vulnerabilities, reportedKeys, path, method, operation,
                            riskScore,
                            "Избыточно доверенная CORS политика",
                            String.format("Эндпоинт %s %s разрешает доступ для всех источников (Allow-Origin: *)." +
                                "Рекомендуется ограничить список доверенных доменов.", method, path),
                            evidence, severity, IMPACT_UNSAFE_ORIGIN, null);
                    } else if (evidence.overlyPermissiveHeaders) {
                        Severity severity = requiresAuth(parser, operation) ? Severity.HIGH : Severity.MEDIUM;
                        severity = applyContextSeverity(severity, context);
                        addCorsVulnerability(vulnerabilities, reportedKeys, path, method, operation,
                            riskScore,
                            "CORS политика допускает чувствительные заголовки",
                            String.format("Эндпоинт %s %s разрешает заголовки %s. Убедитесь, что выдача токенов ограничена.",
                                method, path, evidence.allowedHeaders),
                            evidence, severity, IMPACT_TOKEN_LEAK, null);
                    }
                    if (evidence.allowCredentials && !evidence.hasAllowOrigin) {
                        Severity severity = requiresAuth(parser, operation) ? Severity.CRITICAL : Severity.HIGH;
                        severity = applyContextSeverity(severity, context);
                        addCorsVulnerability(vulnerabilities, reportedKeys, path, method, operation,
                            riskScore,
                            "Allow-Credentials без явного Allow-Origin",
                            String.format("Эндпоинт %s %s разрешает credentials, но не указывает допустимые источники. " +
                                "Уточните список доверенных доменов.", method, path),
                            evidence, severity, IMPACT_CREDENTIALS_MISALIGN,
                            "Всегда указывайте конкретные доверенные origin при использовании Allow-Credentials. Удалите Allow-Credentials, если он не требуется.");
                    }
                    if (evidence.exposesSensitiveHeaders) {
                        Severity severity = requiresAuth(parser, operation) ? Severity.HIGH : Severity.MEDIUM;
                        severity = applyContextSeverity(severity, context);
                        addCorsVulnerability(vulnerabilities, reportedKeys, path, method, operation,
                            riskScore,
                            "Expose-Headers раскрывает чувствительные заголовки",
                            String.format("Эндпоинт %s %s раскрывает через Access-Control-Expose-Headers значения %s. " +
                                "Это может позволить JavaScript-клиенту считывать токены или куки.", method, path, evidence.exposedHeaders),
                            evidence, severity, IMPACT_TOKEN_LEAK, null);
                    }
                    if (evidence.wildcardMethods) {
                        Severity severity = applyContextSeverity(Severity.MEDIUM, context);
                        addCorsVulnerability(vulnerabilities, reportedKeys, path, method, operation,
                            riskScore,
                            "Access-Control-Allow-Methods: *",
                            String.format("Эндпоинт %s %s возвращает Access-Control-Allow-Methods: *. " +
                                "Явно перечислите разрешенные методы.", method, path),
                            evidence, severity, IMPACT_METHOD_WILDCARD, null);
                    }
                    if (evidence.allowPrivateNetworkHeader) {
                        Severity severity = isHighRiskContext(context) ? Severity.CRITICAL : Severity.HIGH;
                        severity = applyContextSeverity(severity, context);
                        if (requiresAuth(parser, operation)) {
                            severity = elevateSeverity(severity);
                        }
                        addCorsVulnerability(vulnerabilities, reportedKeys, path, method, operation,
                            riskScore,
                            "Разрешён доступ к приватной сети",
                            String.format("Эндпоинт %s %s возвращает Access-Control-Allow-Private-Network: true. " +
                                "Удалённый origin может обращаться к ресурсам внутренней сети через браузер.", method, path),
                            evidence, severity, IMPACT_PRIVATE_NETWORK,
                            "Удалите Access-Control-Allow-Private-Network или ограничьте origin до строго контролируемого списка. " +
                                "Для корпоративных API добавьте дополнительную аутентификацию и проверку сети.");
                    }
                    if (!evidence.dangerousOrigins.isEmpty()) {
                        Severity severity = requiresAuth(parser, operation) ? Severity.HIGH : Severity.MEDIUM;
                        severity = applyContextSeverity(severity, context);
                        addCorsVulnerability(vulnerabilities, reportedKeys, path, method, operation,
                            riskScore,
                            "Опасные значения Access-Control-Allow-Origin",
                            String.format("Эндпоинт %s %s разрешает происхождения %s, которые позволяют обходить origin policy (null/file/extension).",
                                method, path, String.join(", ", evidence.dangerousOrigins)),
                            evidence, severity, IMPACT_DANGEROUS_ORIGIN,
                            "Удалите значения вроде null, file://*, chrome-extension://* из Access-Control-Allow-Origin. " +
                                "Используйте проверенный список доменов.");
                    }
                    if (!evidence.localOrigins.isEmpty() || !evidence.privateNetworkOrigins.isEmpty()) {
                        Set<String> combined = new LinkedHashSet<>();
                        combined.addAll(evidence.localOrigins);
                        combined.addAll(evidence.privateNetworkOrigins);
                        Severity severity = requiresAuth(parser, operation) ? Severity.MEDIUM : Severity.LOW;
                        severity = applyContextSeverity(severity, context);
                        addCorsVulnerability(vulnerabilities, reportedKeys, path, method, operation,
                            riskScore,
                            "Разрешены локальные/приватные origin",
                            String.format("Эндпоинт %s %s допускает origin %s (localhost или приватные сети). " +
                                "В production это создаёт риск утечки токенов с локальных приложений.", method, path, String.join(", ", combined)),
                            evidence, severity, IMPACT_DEV_ORIGIN,
                            "Разделяйте dev и production конфигурации CORS. Исключите localhost и приватные IP из production Allow-Origin.");
                    }
                }

                if ("OPTIONS".equals(method) && !documentedCors && !hasCorsHeaders) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id(VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.CORS_MISCONFIGURATION, path, method, null,
                            "CORS policy not documented"))
                        .type(VulnerabilityType.CORS_MISCONFIGURATION)
                        .severity(Severity.LOW)
                        .title("CORS политика не документирована")
                        .description(String.format(
                            "Эндпоинт %s имеет OPTIONS метод (CORS preflight), но CORS политика не описана и заголовки отсутствуют.",
                            path
                        ))
                        .endpoint(path)
                        .method(method)
                        .recommendation(
                            "Четко опишите CORS политику:\n" +
                                "- Allowed origins (не используйте *)\n" +
                                "- Allowed methods\n" +
                                "- Allowed headers\n" +
                                "- Credentials policy"
                        )
                        .owaspCategory("API8:2023 - Security Misconfiguration")
                        .evidence("OPTIONS метод без описания CORS и без Access-Control заголовков")
                        .impactLevel(IMPACT_DEV_ORIGIN)
                        .riskScore(riskScore)
                        .build());
                }
            }
        }
        
        return vulnerabilities;
    }
    
    private boolean requiresAuth(OpenAPIParser parser, Operation operation) {
        return parser != null && parser.requiresAuthentication(operation);
    }

    private Severity elevateSeverity(Severity severity) {
        if (severity == null) {
            return Severity.LOW;
        }
        return switch (severity) {
            case CRITICAL -> Severity.CRITICAL;
            case HIGH -> Severity.CRITICAL;
            case MEDIUM -> Severity.HIGH;
            case LOW -> Severity.MEDIUM;
            case INFO -> Severity.LOW;
        };
    }
    
    private List<Vulnerability> checkErrorHandling(OpenAPI openAPI, ContextAnalyzer.APIContext context) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            Map<String, Operation> operations = getOperationsWithMethods(pathItem);
            for (Map.Entry<String, Operation> opEntry : operations.entrySet()) {
                String method = opEntry.getKey();
                Operation operation = opEntry.getValue();
                if (operation == null || operation.getResponses() == null || operation.getResponses().isEmpty()) {
                    continue;
                }
                
                operation.getResponses().forEach((statusCode, rawResponse) -> {
                    ApiResponse response = resolveApiResponse(rawResponse, openAPI);
                    if (response == null) {
                        return;
                    }
                    
                    int status = parseStatusCode(statusCode);
                    if (status < 400 && !"default".equalsIgnoreCase(statusCode)) {
                        return;
                    }
                    
                    Set<String> samples = new LinkedHashSet<>();
                    if (response.getDescription() != null) {
                        samples.add(response.getDescription().toLowerCase(Locale.ROOT));
                    }
                    if (operation.getSummary() != null) {
                        samples.add(operation.getSummary().toLowerCase(Locale.ROOT));
                    }
                    if (operation.getDescription() != null) {
                        samples.add(operation.getDescription().toLowerCase(Locale.ROOT));
                    }
                    
                    if (response.getContent() != null) {
                        response.getContent().forEach((contentType, mediaType) -> {
                            if (contentType != null) {
                                samples.add(contentType.toLowerCase(Locale.ROOT));
                            }
                            if (mediaType != null) {
                                if (mediaType.getExample() != null) {
                                    samples.add(mediaType.getExample().toString().toLowerCase(Locale.ROOT));
                                }
                                if (mediaType.getExamples() != null) {
                                    mediaType.getExamples().values().stream()
                                        .filter(Objects::nonNull)
                                        .map(Example::getValue)
                                        .filter(Objects::nonNull)
                                        .map(Object::toString)
                                        .map(s -> s.toLowerCase(Locale.ROOT))
                                        .forEach(samples::add);
                                }
                                if (mediaType.getSchema() != null) {
                                    Set<String> schemaSamples = new LinkedHashSet<>();
                                    collectSchemaStrings(mediaType.getSchema(),
                                        schemaSamples,
                                        Collections.newSetFromMap(new IdentityHashMap<Schema<?>, Boolean>()));
                                    schemaSamples.stream()
                                        .map(s -> s.toLowerCase(Locale.ROOT))
                                        .forEach(samples::add);
                                }
                            }
                        });
                    }
                    
                    ErrorExposure exposure = analyzeErrorExposure(samples, status);
                    if (exposure == null) {
                        return;
                    }
                    
                    int riskScore = SmartAnalyzer.calculateRiskScore(path, method, operation, openAPI);
                    Severity severity = determineErrorSeverity(exposure, context);
                    
                    Vulnerability temp = Vulnerability.builder()
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .build();
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SECURITY_MISCONFIGURATION,
                            path,
                            method,
                            statusCode,
                            "Verbose error exposure"))
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .title(exposure.title)
                        .description(exposure.description)
                        .endpoint(path)
                        .method(method)
                        .recommendation(exposure.recommendation)
                        .owaspCategory("API8:2023 - Security Misconfiguration")
                        .evidence(String.format("HTTP %s: %s", statusCode, exposure.evidence))
                        .confidence(ConfidenceCalculator.calculateConfidence(
                            temp, operation, false, true))
                        .priority(ConfidenceCalculator.calculatePriority(
                            temp,
                            ConfidenceCalculator.calculateConfidence(temp, operation, false, true)))
                        .build());
                });
            }
        }
        
        return vulnerabilities;
    }
    
    // ═══════════════════════════════════════════════════════════════
    // НОВЫЕ ПРОВЕРКИ ИЗ EnhancedRules
    // ═══════════════════════════════════════════════════════════════
    
    private List<Vulnerability> checkGraphQL(OpenAPI openAPI, OpenAPIParser parser) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            String pathLower = path != null ? path.toLowerCase(Locale.ROOT) : "";
            
            Map<String, Operation> operations = getOperationsWithMethods(pathItem);
            for (Map.Entry<String, Operation> opEntry : operations.entrySet()) {
                String method = opEntry.getKey();
                Operation op = opEntry.getValue();
                if (op == null) {
                    continue;
                }
                
                Set<String> samples = collectOperationSamples(op);
                String operationText = ((op.getSummary() != null ? op.getSummary() : "") + " " +
                    (op.getDescription() != null ? op.getDescription() : "")).toLowerCase(Locale.ROOT);
                samples.add(operationText);
                samples.add(pathLower);
                
                if (!looksLikeGraphQLEndpoint(pathLower, operationText, samples, op)) {
                    continue;
                }
                
                int riskScore = SmartAnalyzer.calculateRiskScore(path, method, op, openAPI);
                Severity baseSeverity = SmartAnalyzer.severityFromRiskScore(riskScore);
                
                boolean requiresAuth = parser != null && parser.requiresAuthentication(op);
                boolean hasAccessControl = AccessControlHeuristics.hasExplicitAccessControl(op, path, openAPI);
                
                List<String> introspectionHits = findTokens(samples, "__schema", "__type", "introspectionquery", "introspection");
                List<String> depthControlHits = findTokens(samples,
                    "depth limit", "maxdepth", "max depth", "query complexity", "complexity limit", "maxcomplexity");
                List<String> persistedQueryHits = findTokens(samples,
                    "persisted query", "persistedquery", "allowlist", "allow-list", "operation registry", "whitelist", "persisted queries");
                List<String> batchingHits = findTokens(samples, "apollo-batch", "graphql/batch", "query batching", "batch request");
                boolean queryBatchingDetected = !batchingHits.isEmpty();
                boolean mentionsDepthControls = !depthControlHits.isEmpty();
                boolean mutationDetected = samples.stream()
                    .anyMatch(sample -> sample.contains("mutation ") || sample.startsWith("mutation"));
                boolean isGetMethod = "GET".equalsIgnoreCase(method);
                
                if (!requiresAuth && !hasAccessControl) {
                    Severity severity = Severity.CRITICAL;
                    Vulnerability temp = Vulnerability.builder()
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .build();
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, null,
                            "GraphQL эндпоинт без аутентификации"))
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .title("GraphQL эндпоинт доступен без аутентификации")
                        .description("GraphQL эндпоинт " + method + " " + path + " не требует аутентификации и не содержит явных проверок доступа. " +
                            "Это позволяет злоумышленнику выполнять произвольные GraphQL запросы. " +
                            "Без ограничений на introspection (__schema/__type) и глубину/сложность (depth/complexity) значительно возрастает риск атак.")
                        .endpoint(path)
                        .method(method)
                        .recommendation("Добавьте обязательную аутентификацию и проверку ролей/разрешений для GraphQL эндпоинта. " +
                            "Используйте Access-Control tokens, scope'ы и whitelisting операций.")
                        .owaspCategory("API8:2023 - Security Misconfiguration (GraphQL)")
                        .evidence("Security requirements отсутствуют; GraphQL endpoint обнаружен")
                        .confidence(ConfidenceCalculator.calculateConfidence(temp, op, false, true))
                        .priority(ConfidenceCalculator.calculatePriority(
                            temp,
                            ConfidenceCalculator.calculateConfidence(temp, op, false, true)))
                        .build());
                }
                
                if (!introspectionHits.isEmpty()) {
                    Severity severity = (!requiresAuth && !hasAccessControl) ? Severity.CRITICAL : Severity.HIGH;
                    Vulnerability temp = Vulnerability.builder()
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .build();
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, null,
                            "GraphQL introspection включен"))
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .title("Разрешена GraphQL introspection")
                        .description("GraphQL эндпоинт допускает introspection запросы (__schema/__type). " +
                            "Это позволяет злоумышленнику раскрыть структуру API и подготовить целевые атаки.")
                        .endpoint(path)
                        .method(method)
                        .recommendation("Отключите introspection в production (graphql-playground, Apollo, GraphiQL). " +
                            "Используйте allowlist/persisted queries и фильтруйте операции.")
                        .owaspCategory("API8:2023 - Security Misconfiguration (GraphQL Introspection)")
                        .evidence("Найдены индикаторы introspection: " + String.join(", ", introspectionHits))
                        .confidence(ConfidenceCalculator.calculateConfidence(temp, op, false, true))
                        .priority(ConfidenceCalculator.calculatePriority(
                            temp,
                            ConfidenceCalculator.calculateConfidence(temp, op, false, true)))
                        .build());
                }
                
                if (!mentionsDepthControls) {
                    Severity severity = baseSeverity.compareTo(Severity.HIGH) >= 0 ? Severity.HIGH : Severity.MEDIUM;
                    Vulnerability temp = Vulnerability.builder()
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .build();
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, null,
                            "GraphQL depth/complexity ограничение отсутствует"))
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .title("Отсутствует ограничение глубины/сложности GraphQL запросов")
                        .description("GraphQL эндпоинт не описывает ограничения глубины (maxDepth) и сложности (maxComplexity) запросов. " +
                            "Это упрощает атаки типа DoS через глубокие/сложные запросы.")
                        .endpoint(path)
                        .method(method)
                        .recommendation("Задайте maxDepth/maxComplexity, используйте query cost анализ и перехватывайте " +
                            "рекурсивные фрагменты. Ограничьте размер ответа.")
                        .owaspCategory("API8:2023 - Security Misconfiguration (GraphQL Depth)")
                        .evidence("Не обнаружены упоминания depth/complexity limit")
                        .confidence(ConfidenceCalculator.calculateConfidence(temp, op, false, true))
                        .priority(ConfidenceCalculator.calculatePriority(
                            temp,
                            ConfidenceCalculator.calculateConfidence(temp, op, false, true)))
                        .build());
                }
                
                if (persistedQueryHits.isEmpty()) {
                    Severity severity = baseSeverity.compareTo(Severity.HIGH) >= 0 ? Severity.HIGH : Severity.MEDIUM;
                    Vulnerability temp = Vulnerability.builder()
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .build();
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, null,
                            "GraphQL без persisted queries/allowlist"))
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .title("Отсутствует GraphQL allowlist/persisted queries")
                        .description("GraphQL эндпоинт не описывает использование persisted queries или allowlist. " +
                            "Злоумышленник может выполнять произвольные запросы, включая запрещённые операции.")
                        .endpoint(path)
                        .method(method)
                        .recommendation("Включите persisted queries (Apollo Persisted Queries, persisted documents) или " +
                            "allowlist операций. Ограничьте выполнение запросов только заранее зарегистрированными операциями.")
                        .owaspCategory("API8:2023 - Security Misconfiguration (GraphQL Allowlist)")
                        .evidence("Не обнаружены токены allowlist/persisted queries для GraphQL endpoint")
                        .confidence(ConfidenceCalculator.calculateConfidence(temp, op, false, true))
                        .priority(ConfidenceCalculator.calculatePriority(
                            temp,
                            ConfidenceCalculator.calculateConfidence(temp, op, false, true)))
                        .build());
                }
                
                if (mutationDetected && (!requiresAuth || !hasAccessControl)) {
                    Severity severity = Severity.CRITICAL;
                    Vulnerability temp = Vulnerability.builder()
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .build();
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, null,
                            "GraphQL mutation без авторизации"))
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .title("GraphQL mutation без аутентификации/consent")
                        .description("GraphQL endpoint " + method + " " + path + " допускает выполнение mutation, но не требует " +
                            "обязательной авторизации/consent. Это позволяет злоумышленнику изменять данные без согласия.")
                        .endpoint(path)
                        .method(method)
                        .recommendation("Требуйте auth tokens и проверки consent для mutation. Используйте разделение схем (read/write) " +
                            "и роль-based access control.")
                        .owaspCategory("API8:2023 - Security Misconfiguration (GraphQL Mutation)")
                        .evidence("Обнаружены индикаторы mutation в описании/примерах, отсутствие security requirements")
                        .confidence(ConfidenceCalculator.calculateConfidence(temp, op, false, true))
                        .priority(ConfidenceCalculator.calculatePriority(
                            temp,
                            ConfidenceCalculator.calculateConfidence(temp, op, false, true)))
                        .build());
                }
                
                if (queryBatchingDetected && (!requiresAuth || !hasAccessControl)) {
                    Severity severity = baseSeverity.compareTo(Severity.HIGH) >= 0 ? Severity.HIGH : Severity.MEDIUM;
                    Vulnerability temp = Vulnerability.builder()
                        .type(VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .build();
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION, path, method, null,
                            "GraphQL batching без лимитов"))
                        .type(VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .title("GraphQL batching без rate limiting")
                        .description("GraphQL endpoint " + method + " " + path + " допускает batching/мультизапросы и не описывает " +
                            "ограничения по rate limit. Это позволяет злоумышленнику инициировать DoS через объединённые payload.")
                        .endpoint(path)
                        .method(method)
                        .recommendation("Отключите batching или установите строгие лимиты (maxBatchSize, throttle). " +
                            "Используйте per-client rate limiting и анализируйте query cost.")
                        .owaspCategory("API4:2023 - Unrestricted Resource Consumption (GraphQL Batching)")
                        .evidence("Обнаружены индикаторы batching: " + String.join(", ", batchingHits))
                        .confidence(ConfidenceCalculator.calculateConfidence(temp, op, false, true))
                        .priority(ConfidenceCalculator.calculatePriority(
                            temp,
                            ConfidenceCalculator.calculateConfidence(temp, op, false, true)))
                        .build());
                }
                
                if (isGetMethod) {
                    Severity severity = Severity.MEDIUM;
                    Vulnerability temp = Vulnerability.builder()
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .build();
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, null,
                            "GraphQL GET метод разрешен"))
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(severity)
                        .riskScore(riskScore)
                        .title("GraphQL запросы разрешены через GET")
                        .description("GraphQL запросы выполняются через GET. Это повышает риск утечки чувствительных данных " +
                            "в URL, логах, кешах и прокси.")
                        .endpoint(path)
                        .method(method)
                        .recommendation("Ограничьте GraphQL взаимодействие методом POST. Используйте CSRF-защиту и запрещайте " +
                            "кэширование URL с чувствительными данными.")
                        .owaspCategory("API8:2023 - Security Misconfiguration (GraphQL)")
                        .evidence("Method " + method + " разрешен для GraphQL")
                        .confidence(ConfidenceCalculator.calculateConfidence(temp, op, false, true))
                        .priority(ConfidenceCalculator.calculatePriority(
                            temp,
                            ConfidenceCalculator.calculateConfidence(temp, op, false, true)))
                        .build());
                }
            }
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkIoT(OpenAPI openAPI, OpenAPIParser parser) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) return vulnerabilities;
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // Перебираем операции с их методами
            if (pathItem.getGet() != null) {
                checkIoTOperation(path, "GET", pathItem.getGet(), openAPI, parser, vulnerabilities);
            }
            if (pathItem.getPost() != null) {
                checkIoTOperation(path, "POST", pathItem.getPost(), openAPI, parser, vulnerabilities);
            }
            if (pathItem.getPut() != null) {
                checkIoTOperation(path, "PUT", pathItem.getPut(), openAPI, parser, vulnerabilities);
            }
            if (pathItem.getDelete() != null) {
                checkIoTOperation(path, "DELETE", pathItem.getDelete(), openAPI, parser, vulnerabilities);
            }
            if (pathItem.getPatch() != null) {
                checkIoTOperation(path, "PATCH", pathItem.getPatch(), openAPI, parser, vulnerabilities);
            }
        }
        
        return vulnerabilities;
    }
    
    private List<String> resolveServerUrls(OpenAPI openAPI, PathItem pathItem, Operation operation) {
        LinkedHashSet<String> urls = new LinkedHashSet<>();
        if (operation != null && operation.getServers() != null) {
            operation.getServers().stream()
                .map(Server::getUrl)
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .forEach(urls::add);
        }
        if (pathItem != null && pathItem.getServers() != null) {
            pathItem.getServers().stream()
                .map(Server::getUrl)
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .forEach(urls::add);
        }
        if (openAPI != null && openAPI.getServers() != null) {
            openAPI.getServers().stream()
                .map(Server::getUrl)
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .forEach(urls::add);
        }
        return new ArrayList<>(urls);
    }
    
    private boolean looksLikeGrpcEndpoint(String pathLower, Set<String> samples, Operation operation) {
        if (pathLower.contains("grpc") || pathLower.endsWith(".grpc") || pathLower.endsWith(".proto")) {
            return true;
        }
        for (String sample : samples) {
            if (sample.contains("grpc") || sample.contains("protobuf") || sample.contains("proto3")
                || sample.contains("rpc service") || sample.contains("google.rpc")) {
                return true;
            }
        }
        if (operation != null && operation.getExtensions() != null) {
            for (Map.Entry<String, Object> extension : operation.getExtensions().entrySet()) {
                String key = extension.getKey() != null ? extension.getKey().toLowerCase(Locale.ROOT) : "";
                String value = extension.getValue() != null ? extension.getValue().toString().toLowerCase(Locale.ROOT) : "";
                if (key.contains("grpc") || value.contains("grpc") || value.contains("proto")) {
                    return true;
                }
            }
        }
        return hasGrpcContent(operation);
    }
    
    private boolean hasGrpcContent(Operation operation) {
        if (operation == null) {
            return false;
        }
        if (operation.getRequestBody() != null && operation.getRequestBody().getContent() != null) {
            for (String media : operation.getRequestBody().getContent().keySet()) {
                if (isGrpcMedia(media)) {
                    return true;
                }
            }
        }
        if (operation.getResponses() != null) {
            for (ApiResponse response : operation.getResponses().values()) {
                if (response == null || response.getContent() == null) {
                    continue;
                }
                for (String media : response.getContent().keySet()) {
                    if (isGrpcMedia(media)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    private boolean isGrpcMedia(String media) {
        if (media == null) {
            return false;
        }
        String lower = media.toLowerCase(Locale.ROOT);
        return lower.contains("grpc") || lower.contains("protobuf") || lower.contains("proto")
            || lower.contains("application/octet-stream");
    }
    
    private boolean isSecureGrpcUrl(String url) {
        if (url == null) {
            return false;
        }
        String lower = url.toLowerCase(Locale.ROOT);
        return lower.startsWith("https://") || lower.startsWith("grpcs://");
    }
    
    private boolean isInsecureGrpcUrl(String url) {
        if (url == null) {
            return false;
        }
        String lower = url.toLowerCase(Locale.ROOT);
        return lower.startsWith("http://") || lower.startsWith("grpc://");
    }
    
    private boolean looksLikeWebSocketEndpoint(String pathLower, Set<String> samples, Operation operation) {
        if (pathLower.contains("websocket") || pathLower.contains("/ws") || pathLower.contains("/socket")) {
            return true;
        }
        for (String sample : samples) {
            if (sample.contains("websocket") || sample.contains("ws://") || sample.contains("wss://")
                || sample.contains("socket.io") || sample.contains("sockjs") || sample.contains("stomp")
                || sample.contains("realtime") || sample.contains("pubsub")) {
                return true;
            }
        }
        if (operation != null && operation.getExtensions() != null) {
            for (Map.Entry<String, Object> extension : operation.getExtensions().entrySet()) {
                String key = extension.getKey() != null ? extension.getKey().toLowerCase(Locale.ROOT) : "";
                String value = extension.getValue() != null ? extension.getValue().toString().toLowerCase(Locale.ROOT) : "";
                if (key.contains("websocket") || value.contains("websocket") || key.contains("ws")) {
                    return true;
                }
            }
        }
        if (operation != null && operation.getParameters() != null) {
            for (io.swagger.v3.oas.models.parameters.Parameter parameter : operation.getParameters()) {
                if (parameter == null || parameter.getName() == null) {
                    continue;
                }
                String name = parameter.getName().toLowerCase(Locale.ROOT);
                if (name.contains("sec-websocket") || name.contains("websocket")) {
                    return true;
                }
            }
        }
        return false;
    }
    
    private boolean isSecureWebSocketUrl(String url) {
        if (url == null) {
            return false;
        }
        String lower = url.toLowerCase(Locale.ROOT);
        return lower.startsWith("wss://") || lower.startsWith("https://");
    }
    
    private boolean isInsecureWebSocketUrl(String url) {
        if (url == null) {
            return false;
        }
        String lower = url.toLowerCase(Locale.ROOT);
        return lower.startsWith("ws://") || lower.startsWith("http://");
    }
    
    private Map<String, Operation> getOperationsWithMethods(PathItem pathItem) {
        Map<String, Operation> operations = new LinkedHashMap<>();
        if (pathItem.getGet() != null) operations.put("GET", pathItem.getGet());
        if (pathItem.getPost() != null) operations.put("POST", pathItem.getPost());
        if (pathItem.getPut() != null) operations.put("PUT", pathItem.getPut());
        if (pathItem.getDelete() != null) operations.put("DELETE", pathItem.getDelete());
        if (pathItem.getPatch() != null) operations.put("PATCH", pathItem.getPatch());
        if (pathItem.getOptions() != null) operations.put("OPTIONS", pathItem.getOptions());
        if (pathItem.getHead() != null) operations.put("HEAD", pathItem.getHead());
        if (pathItem.getTrace() != null) operations.put("TRACE", pathItem.getTrace());
        return operations;
    }

    private boolean hasCorsDocumentation(Operation operation) {
        if (operation == null) {
            return false;
        }
        String text = ((operation.getDescription() != null ? operation.getDescription() : "") +
            (operation.getSummary() != null ? operation.getSummary() : "")).toLowerCase(Locale.ROOT);
        return text.contains("cors") || text.contains("cross-origin") || text.contains("access-control");
    }

    private ApiResponse resolveApiResponse(ApiResponse response, OpenAPI openAPI) {
        if (response == null) {
            return null;
        }
        if (response.get$ref() == null || openAPI == null || openAPI.getComponents() == null ||
            openAPI.getComponents().getResponses() == null) {
            return response;
        }
        String ref = response.get$ref();
        String name = ref.substring(ref.lastIndexOf('/') + 1);
        ApiResponse resolved = openAPI.getComponents().getResponses().get(name);
        return resolved != null ? resolved : response;
    }

    private CorsEvidence extractCorsHeaders(ApiResponse response) {
        CorsEvidence evidence = new CorsEvidence();
        if (response == null || response.getHeaders() == null || response.getHeaders().isEmpty()) {
            return evidence;
        }

        Map<String, Header> headers = response.getHeaders();
        Header allowOriginHeader = getHeaderIgnoreCase(headers, "Access-Control-Allow-Origin");
        resolveHeaderValue(allowOriginHeader).ifPresent(value -> {
            evidence.hasAllowOrigin = true;
            splitHeaderValues(value).forEach(originValue -> {
                String normalized = normalizeOriginValue(originValue);
                if (normalized.isEmpty()) {
                    return;
                }
                evidence.allowedOrigins.add(normalized);
                if ("*".equals(normalized)) {
                    evidence.wildcardOrigin = true;
                } else {
                    analyzeOrigin(normalized, evidence);
                }
            });
        });

        Header allowCredentialsHeader = getHeaderIgnoreCase(headers, "Access-Control-Allow-Credentials");
        evidence.allowCredentials = resolveHeaderValue(allowCredentialsHeader)
            .map(val -> "true".equalsIgnoreCase(val.trim()))
            .orElse(false);
        evidence.wildcardAndCredentials = evidence.allowCredentials && evidence.wildcardOrigin;
        evidence.missingAllowOrigin = evidence.allowCredentials && !evidence.hasAllowOrigin;

        Header allowHeadersHeader = getHeaderIgnoreCase(headers, "Access-Control-Allow-Headers");
        resolveHeaderValue(allowHeadersHeader).ifPresent(value -> {
            splitHeaderValues(value).forEach(header -> {
                evidence.allowedHeaders.add(header);
                String lower = header.toLowerCase(Locale.ROOT);
                if (SENSITIVE_CORS_HEADERS.contains(lower)) {
                    evidence.overlyPermissiveHeaders = true;
                }
            });
        });

        Header allowMethodsHeader = getHeaderIgnoreCase(headers, "Access-Control-Allow-Methods");
        resolveHeaderValue(allowMethodsHeader).ifPresent(value -> splitHeaderValues(value).forEach(method -> {
            evidence.allowedMethods.add(method);
            if ("*".equals(method.trim()) || "any".equalsIgnoreCase(method.trim())) {
                evidence.wildcardMethods = true;
            }
        }));

        Header exposeHeadersHeader = getHeaderIgnoreCase(headers, "Access-Control-Expose-Headers");
        resolveHeaderValue(exposeHeadersHeader).ifPresent(value -> {
            splitHeaderValues(value).forEach(header -> {
                evidence.exposedHeaders.add(header);
                String lower = header.toLowerCase(Locale.ROOT);
                if (SENSITIVE_EXPOSE_HEADERS.contains(lower)) {
                    evidence.exposesSensitiveHeaders = true;
                }
            });
        });

        Header allowPrivateNetworkHeader = getHeaderIgnoreCase(headers, "Access-Control-Allow-Private-Network");
        resolveHeaderValue(allowPrivateNetworkHeader).ifPresent(value -> {
            if ("true".equalsIgnoreCase(value.trim())) {
                evidence.allowPrivateNetworkHeader = true;
            }
        });

        return evidence;
    }

    private void addCorsVulnerability(List<Vulnerability> vulnerabilities,
                                      Set<String> reportedKeys,
                                      String path,
                                      String method,
                                      Operation operation,
                                      int riskScore,
                                      String title,
                                      String description,
                                      CorsEvidence evidence,
                                      Severity severity,
                                      String impact,
                                      String recommendation) {
        String dedupeKey = String.format("%s|%s|%s", path, method, title);
        if (reportedKeys != null && !reportedKeys.add(dedupeKey)) {
            return;
        }

        Vulnerability temp = Vulnerability.builder()
            .type(VulnerabilityType.CORS_MISCONFIGURATION)
            .severity(severity)
            .riskScore(riskScore)
            .build();

        int confidence = ConfidenceCalculator.calculateConfidence(temp, operation, false, true);
        vulnerabilities.add(Vulnerability.builder()
            .id(VulnerabilityIdGenerator.generateId(
                VulnerabilityType.CORS_MISCONFIGURATION, path, method, null, title))
            .type(VulnerabilityType.CORS_MISCONFIGURATION)
            .severity(severity)
            .riskScore(riskScore)
            .title(title)
            .description(description)
            .endpoint(path)
            .method(method)
            .impactLevel(impact)
            .recommendation(recommendation != null ? recommendation :
                "Уточните CORS-политику:\n" +
                    "- Используйте whitelists доверенных доменов\n" +
                    "- Не комбинируйте Allow-Origin: * с Credentials=true\n" +
                    "- Ограничьте Allow-Headers и Allow-Methods"
            )
            .owaspCategory("API8:2023 - Security Misconfiguration")
            .evidence(evidence.describe())
            .confidence(confidence)
            .priority(ConfidenceCalculator.calculatePriority(temp, confidence))
            .build());
    }

    private Header getHeaderIgnoreCase(Map<String, Header> headers, String target) {
        if (headers == null || headers.isEmpty()) {
            return null;
        }
        for (Map.Entry<String, Header> entry : headers.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(target)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private Optional<String> resolveHeaderValue(Header header) {
        if (header == null) {
            return Optional.empty();
        }
        if (header.getExample() != null) {
            return Optional.of(header.getExample().toString());
        }
        if (header.getExamples() != null) {
            for (Example example : header.getExamples().values()) {
                if (example != null && example.getValue() != null) {
                    return Optional.of(example.getValue().toString());
                }
            }
        }
        Schema<?> schema = header.getSchema();
        if (schema != null) {
            if (schema.getExample() != null) {
                return Optional.of(schema.getExample().toString());
            }
            if (schema.getDefault() != null) {
                return Optional.of(schema.getDefault().toString());
            }
            if (schema.getEnum() != null && !schema.getEnum().isEmpty()) {
                Object first = schema.getEnum().get(0);
                if (first != null) {
                    return Optional.of(first.toString());
                }
            }
        }
        return Optional.empty();
    }

    private List<String> splitHeaderValues(String headerValue) {
        if (headerValue == null) {
            return Collections.emptyList();
        }
        return Stream.of(headerValue.split(","))
            .map(String::trim)
            .filter(value -> !value.isEmpty())
            .toList();
    }

    private String normalizeOriginValue(String origin) {
        if (origin == null) {
            return "";
        }
        String result = origin.trim();
        if ((result.startsWith("\"") && result.endsWith("\"")) || (result.startsWith("'") && result.endsWith("'"))) {
            result = result.substring(1, result.length() - 1);
        }
        return result.trim();
    }

    private void analyzeOrigin(String origin, CorsEvidence evidence) {
        if (origin == null || origin.isBlank()) {
            return;
        }
        String lower = origin.toLowerCase(Locale.ROOT);
        if (DANGEROUS_ORIGIN_VALUES.contains(lower)) {
            evidence.dangerousOrigins.add(origin);
            return;
        }
        for (String prefix : DANGEROUS_ORIGIN_PREFIXES) {
            if (lower.startsWith(prefix)) {
                evidence.dangerousOrigins.add(origin);
                return;
            }
        }
        if (lower.contains("localhost")) {
            evidence.localOrigins.add(origin);
        }
        try {
            URI uri = new URI(origin);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null && origin.startsWith("//")) {
                uri = new URI("https:" + origin);
                host = uri.getHost();
            } else if (scheme == null) {
                uri = new URI("https://" + origin);
                host = uri.getHost();
            }
            if (scheme != null && DANGEROUS_ORIGIN_PREFIXES.stream().anyMatch(prefix -> scheme.startsWith(prefix.replace("://", "")))) {
                evidence.dangerousOrigins.add(origin);
            }
            if (host != null) {
                String hostLower = host.toLowerCase(Locale.ROOT);
                if (isLoopback(hostLower)) {
                    evidence.localOrigins.add(origin);
                } else if (isPrivateAddress(hostLower)) {
                    evidence.privateNetworkOrigins.add(origin);
                }
            }
        } catch (URISyntaxException ignored) {
            if (lower.startsWith("http://") || lower.startsWith("https://")) {
                String hostPart = lower;
                int schemeSeparator = lower.indexOf("://");
                if (schemeSeparator > 0) {
                    hostPart = lower.substring(schemeSeparator + 3);
                }
                int slashIndex = hostPart.indexOf('/');
                if (slashIndex > 0) {
                    hostPart = hostPart.substring(0, slashIndex);
                }
                if (isLoopback(hostPart)) {
                    evidence.localOrigins.add(origin);
                } else if (isPrivateAddress(hostPart)) {
                    evidence.privateNetworkOrigins.add(origin);
                }
            }
        }
    }

    private boolean isLoopback(String host) {
        if (host == null) {
            return false;
        }
        if (LOOPBACK_HOSTS.contains(host)) {
            return true;
        }
        return host.startsWith("localhost") || host.endsWith(".localhost");
    }

    private boolean isPrivateAddress(String host) {
        if (host == null) {
            return false;
        }
        String normalized = host;
        if (normalized.startsWith("[")) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        if (PRIVATE_IPV4_PATTERN.matcher(normalized).matches()) {
            return true;
        }
        if (PRIVATE_IPV6_PATTERN.matcher(normalized).matches()) {
            return true;
        }
        return normalized.endsWith(".local") || normalized.endsWith(".lan") || normalized.endsWith(".internal");
    }

    private boolean isHighRiskContext(ContextAnalyzer.APIContext context) {
        return context != null && HIGH_RISK_CONTEXTS.contains(context);
    }

    private Severity applyContextSeverity(Severity severity, ContextAnalyzer.APIContext context) {
        if (severity == null) {
            return Severity.LOW;
        }
        if (!isHighRiskContext(context)) {
            return severity;
        }
        return elevateSeverity(severity);
    }

    private static class CorsEvidence {
        boolean hasAllowOrigin;
        boolean wildcardOrigin;
        boolean allowCredentials;
        boolean wildcardAndCredentials;
        boolean overlyPermissiveHeaders;
        boolean missingAllowOrigin;
        boolean wildcardMethods;
        boolean exposesSensitiveHeaders;
        boolean allowPrivateNetworkHeader;
        final Set<String> allowedOrigins = new LinkedHashSet<>();
        final Set<String> allowedHeaders = new LinkedHashSet<>();
        final Set<String> allowedMethods = new LinkedHashSet<>();
        final Set<String> exposedHeaders = new LinkedHashSet<>();
        final Set<String> dangerousOrigins = new LinkedHashSet<>();
        final Set<String> localOrigins = new LinkedHashSet<>();
        final Set<String> privateNetworkOrigins = new LinkedHashSet<>();

        boolean isEmpty() {
            return !hasAllowOrigin &&
                allowedHeaders.isEmpty() &&
                allowedMethods.isEmpty() &&
                !allowCredentials &&
                !allowPrivateNetworkHeader &&
                dangerousOrigins.isEmpty() &&
                localOrigins.isEmpty() &&
                privateNetworkOrigins.isEmpty();
        }

        String describe() {
            StringBuilder builder = new StringBuilder();
            if (hasAllowOrigin) {
                builder.append("Access-Control-Allow-Origin: ")
                    .append(allowedOrigins.isEmpty() ? "(значение не указано)" : String.join(", ", allowedOrigins))
                    .append(". ");
            }
            if (missingAllowOrigin) {
                builder.append("Allow-Credentials: true, но Allow-Origin отсутствует. ");
            }
            if (allowCredentials) {
                builder.append("Access-Control-Allow-Credentials: true. ");
            }
            if (allowPrivateNetworkHeader) {
                builder.append("Access-Control-Allow-Private-Network: true. ");
            }
            if (!allowedHeaders.isEmpty()) {
                builder.append("Access-Control-Allow-Headers: ")
                    .append(String.join(", ", allowedHeaders)).append(". ");
            }
            if (!allowedMethods.isEmpty()) {
                builder.append("Access-Control-Allow-Methods: ")
                    .append(String.join(", ", allowedMethods)).append(". ");
            }
            if (!exposedHeaders.isEmpty()) {
                builder.append("Access-Control-Expose-Headers: ")
                    .append(String.join(", ", exposedHeaders)).append(". ");
            }
            if (!dangerousOrigins.isEmpty()) {
                builder.append("Опасные origin: ")
                    .append(String.join(", ", dangerousOrigins)).append(". ");
            }
            if (!localOrigins.isEmpty()) {
                builder.append("Локальные origin: ")
                    .append(String.join(", ", localOrigins)).append(". ");
            }
            if (!privateNetworkOrigins.isEmpty()) {
                builder.append("Приватные origin: ")
                    .append(String.join(", ", privateNetworkOrigins)).append(". ");
            }
            return builder.toString().trim();
        }
    }

    private Set<String> collectOperationSamples(Operation op) {
        Set<String> samples = new LinkedHashSet<>();
        if (op == null) {
            return samples;
        }
        if (op.getSummary() != null) {
            addSample(samples, op.getSummary());
        }
        if (op.getDescription() != null) {
            addSample(samples, op.getDescription());
        }
        if (op.getParameters() != null) {
            for (io.swagger.v3.oas.models.parameters.Parameter parameter : op.getParameters()) {
                if (parameter == null) {
                    continue;
                }
                addSample(samples, parameter.getName());
                addSample(samples, parameter.getDescription());
                addSample(samples, parameter.getIn());
                if (parameter.getExample() != null) {
                    addSample(samples, parameter.getExample());
                }
                if (parameter.getExamples() != null) {
                    parameter.getExamples().values().stream()
                        .filter(Objects::nonNull)
                        .map(Example::getValue)
                        .filter(Objects::nonNull)
                        .forEach(value -> addSample(samples, value));
                }
                Schema<?> parameterSchema = parameter.getSchema();
                if (parameterSchema != null) {
                    collectSchemaStrings(parameterSchema, samples, Collections.newSetFromMap(new IdentityHashMap<Schema<?>, Boolean>()));
                }
            }
        }
        if (op.getRequestBody() != null && op.getRequestBody().getContent() != null) {
            for (Map.Entry<String, MediaType> entry : op.getRequestBody().getContent().entrySet()) {
                if (entry.getKey() != null) {
                    addSample(samples, entry.getKey());
                }
                MediaType mediaType = entry.getValue();
                if (mediaType == null) {
                    continue;
                }
                if (mediaType.getExample() != null) {
                    addSample(samples, mediaType.getExample());
                }
                if (mediaType.getExamples() != null) {
                    mediaType.getExamples().values().stream()
                        .filter(Objects::nonNull)
                        .map(Example::getValue)
                        .filter(Objects::nonNull)
                        .forEach(value -> addSample(samples, value));
                }
                Schema<?> bodySchema = mediaType.getSchema();
                if (bodySchema != null) {
                    collectSchemaStrings(bodySchema, samples, Collections.newSetFromMap(new IdentityHashMap<Schema<?>, Boolean>()));
                }
            }
        }
        if (op.getCallbacks() != null) {
            op.getCallbacks().values().forEach(callback -> {
                if (callback == null) {
                    return;
                }
                callback.values().forEach(callbackPathItem -> {
                    if (callbackPathItem == null) {
                        return;
                    }
                    Map<String, Operation> operations = getOperationsWithMethods(callbackPathItem);
                    operations.values().forEach(callbackOperation -> samples.addAll(collectOperationSamples(callbackOperation)));
                });
            });
        }
        return samples;
    }

    private void collectSchemaStrings(Schema<?> schema, Set<String> samples, Set<Schema<?>> visited) {
        if (schema == null || !visited.add(schema)) {
            return;
        }
        addSample(samples, schema.getTitle());
        addSample(samples, schema.getDescription());
        addSample(samples, schema.getFormat());
        addSample(samples, schema.getPattern());
        if (schema.getExample() != null) {
            addSample(samples, schema.getExample());
        }
        if (schema.getDefault() != null) {
            addSample(samples, schema.getDefault());
        }
        if (schema.getConst() != null) {
            addSample(samples, schema.getConst());
        }
        if (schema.getEnum() != null) {
            schema.getEnum().stream()
                .filter(Objects::nonNull)
                .forEach(value -> addSample(samples, value));
        }
        if (schema.getProperties() != null) {
            schema.getProperties().forEach((key, value) -> {
                addSample(samples, key);
                if (value instanceof Schema<?> propertySchema) {
                    collectSchemaStrings(propertySchema, samples, visited);
                }
            });
        }
        if (schema.getItems() != null) {
            collectSchemaStrings(schema.getItems(), samples, visited);
        }
        if (schema.getAllOf() != null) {
            schema.getAllOf().forEach(sub -> collectSchemaStrings(sub, samples, visited));
        }
        if (schema.getOneOf() != null) {
            schema.getOneOf().forEach(sub -> collectSchemaStrings(sub, samples, visited));
        }
        if (schema.getAnyOf() != null) {
            schema.getAnyOf().forEach(sub -> collectSchemaStrings(sub, samples, visited));
        }
        Object additional = schema.getAdditionalProperties();
        if (additional instanceof Schema<?> additionalSchema) {
            collectSchemaStrings(additionalSchema, samples, visited);
        }
    }

    private void addSample(Set<String> samples, Object value) {
        if (value == null) {
            return;
        }
        String text = String.valueOf(value).trim();
        if (!text.isEmpty()) {
            samples.add(text.toLowerCase(Locale.ROOT));
        }
    }

    private List<String> findTokens(Set<String> samples, String... tokens) {
        Set<String> hits = new LinkedHashSet<>();
        for (String token : tokens) {
            if (token == null || token.isBlank()) {
                continue;
            }
            String lowered = token.toLowerCase(Locale.ROOT);
            for (String sample : samples) {
                if (sample.contains(lowered)) {
                    hits.add(token);
                    break;
                }
            }
        }
        return new ArrayList<>(hits);
    }

    private boolean looksLikeGraphQLEndpoint(String pathLower,
                                             String operationText,
                                             Set<String> samples,
                                             Operation operation) {
        if (pathLower.contains("graphql") || pathLower.endsWith("/graph")) {
            return true;
        }
        if (operationText.contains("graphql") || operationText.contains("graph ql")) {
            return true;
        }
        if (samples.stream().anyMatch(sample -> sample.contains("graphql") || sample.contains("introspectionquery"))) {
            return true;
        }
        if (hasGraphQLContentType(operation)) {
            return true;
        }
        return hasGraphQLParameters(operation);
    }

    private boolean hasGraphQLContentType(Operation operation) {
        if (operation == null || operation.getRequestBody() == null ||
            operation.getRequestBody().getContent() == null) {
            return false;
        }
        return operation.getRequestBody().getContent().keySet().stream()
            .filter(Objects::nonNull)
            .map(ct -> ct.toLowerCase(Locale.ROOT))
            .anyMatch(ct -> ct.contains("graphql"));
    }

    private boolean hasGraphQLParameters(Operation operation) {
        if (operation == null || operation.getParameters() == null) {
            return false;
        }
        for (io.swagger.v3.oas.models.parameters.Parameter parameter : operation.getParameters()) {
            if (parameter == null || parameter.getName() == null) {
                continue;
            }
            String lower = parameter.getName().toLowerCase(Locale.ROOT);
            if (lower.contains("graphql") || lower.equals("query") || lower.contains("introspection")) {
                return true;
            }
            if (EnhancedRules.isGraphQLRisk(parameter)) {
                return true;
            }
        }
        return false;
    }

    private int parseStatusCode(String statusCode) {
        if (statusCode == null) {
            return 0;
        }
        String trimmed = statusCode.trim().toUpperCase(Locale.ROOT);
        if ("DEFAULT".equals(trimmed)) {
            return 500;
        }
        try {
            return Integer.parseInt(trimmed);
        } catch (NumberFormatException ex) {
            if (trimmed.length() == 3 && Character.isDigit(trimmed.charAt(0)) && trimmed.endsWith("XX")) {
                return (trimmed.charAt(0) - '0') * 100;
            }
            return 0;
        }
    }

    private ErrorExposure analyzeErrorExposure(Set<String> samples, int statusCode) {
        if (samples == null || samples.isEmpty()) {
            return null;
        }
        List<String> stackHits = findTokens(samples, STACK_TRACE_TOKENS.toArray(new String[0]));
        if (!stackHits.isEmpty()) {
            return new ErrorExposure(
                "STACK_TRACE",
                "Утечка технических деталей в сообщениях об ошибках",
                "Ответ API содержит признаки stack trace/traceback. Это раскрывает структуру приложения и библиотек, " +
                    "облегчая эксплуатацию уязвимостей.",
                "Возвращайте клиенту только user-friendly сообщение об ошибке. Полные stack trace логируйте на сервере, " +
                    "используйте error id для корреляции. В production включите generic error handler.",
                String.join(", ", stackHits)
            );
        }
        List<String> sqlHits = findTokens(samples, SQL_TOKENS.toArray(new String[0]));
        if (!sqlHits.isEmpty()) {
            return new ErrorExposure(
                "SQL_DEBUG",
                "SQL/База данных раскрыта в ответе",
                "Ответ содержит SQL-конструкции или названия СУБД. Это упрощает построение SQL-инъекций и выявление структуры базы.",
                "Спрячьте технические детали БД. Используйте обёртки ошибок, заменяйте текст на пользовательский. " +
                    "Проверьте, что ORM/DAO прослойка не пропускает исключения наружу.",
                String.join(", ", sqlHits)
            );
        }
        List<String> debugHits = findTokens(samples, DEBUG_TOKENS.toArray(new String[0]));
        if (!debugHits.isEmpty()) {
            return new ErrorExposure(
                "DEBUG_INFO",
                "Подробные диагностические сообщения доступны клиенту",
                "Ответ содержит внутренние идентификаторы (trace id, correlation id) или ключевые слова debug. " +
                    "Злоумышленник может использовать их для перебора и корреляции событий.",
                "Оставляйте диагностику только в логах. Клиенту возвращайте дружественное сообщение и, при необходимости, " +
                    "короткий внешний идентификатор, не связанный напрямую с внутренними системами.",
                String.join(", ", debugHits)
            );
        }
        List<String> techHits = findTokens(samples, TECHNOLOGY_TOKENS.toArray(new String[0]));
        if (!techHits.isEmpty() && statusCode >= 500) {
            return new ErrorExposure(
                "TECH_STACK",
                "Раскрывается стек технологий через ошибки 5xx",
                "Ответы 5xx содержат названия фреймворков/серверов. Это помогает атакующему подобрать эксплойты под конкретный стек.",
                "Перехватывайте необработанные исключения и заменяйте ответ на унифицированный JSON с кодом ошибки. " +
                    "Проверьте глобальные обработчики ошибок и настройки production профиля.",
                String.join(", ", techHits)
            );
        }
        return null;
    }

    private Severity determineErrorSeverity(ErrorExposure exposure, ContextAnalyzer.APIContext context) {
        boolean highContext = context == ContextAnalyzer.APIContext.BANKING ||
            context == ContextAnalyzer.APIContext.GOVERNMENT ||
            context == ContextAnalyzer.APIContext.HEALTHCARE;
        return switch (exposure.type) {
            case "STACK_TRACE", "SQL_DEBUG" -> highContext ? Severity.CRITICAL : Severity.HIGH;
            case "DEBUG_INFO" -> highContext ? Severity.HIGH : Severity.MEDIUM;
            case "TECH_STACK" -> highContext ? Severity.HIGH : Severity.MEDIUM;
            default -> highContext ? Severity.HIGH : Severity.MEDIUM;
        };
    }

    private static class ErrorExposure {
        final String type;
        final String title;
        final String description;
        final String recommendation;
        final String evidence;

        ErrorExposure(String type, String title, String description, String recommendation, String evidence) {
            this.type = type;
            this.title = title;
            this.description = description;
            this.recommendation = recommendation;
            this.evidence = evidence;
        }
    }

    private void checkIoTOperation(String path, String method, Operation op, OpenAPI openAPI, OpenAPIParser parser, List<Vulnerability> vulnerabilities) {
        if (op == null) {
            return;
        }
        
        Set<String> samples = collectOperationSamples(op);
        List<String> indicatorHits = new ArrayList<>(findTokens(samples,
            "iot", "device", "sensor", "actuator", "firmware", "ota", "over-the-air",
            "mqtt", "coap", "telemetry", "shadow", "provision", "thing", "lwm2m", "edge",
            "gateway", "device binding", "trusted device", "psu-device",
            "устройство", "датчик", "актуатор", "телеметрия", "прошивка", "шлюз"));
        
        if (op.getParameters() != null) {
            for (io.swagger.v3.oas.models.parameters.Parameter param : op.getParameters()) {
                if (EnhancedRules.isIoTRisk(param)) {
                    indicatorHits.add("param:" + param.getName());
                }
            }
        }
        
        boolean hasIndicators = !indicatorHits.isEmpty();
        if (hasIndicators) {
            boolean requiresAuth = parser != null && parser.requiresAuthentication(op);
            boolean hasAccessControl = AccessControlHeuristics.hasExplicitAccessControl(op, path, openAPI);
            if (!requiresAuth && !hasAccessControl) {
                int riskScore = SmartAnalyzer.calculateRiskScore(path, method, op, openAPI);
                Severity severity = Severity.CRITICAL;
                Vulnerability temp = Vulnerability.builder()
                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                    .severity(severity)
                    .riskScore(riskScore)
                    .build();
                
                vulnerabilities.add(Vulnerability.builder()
                    .id(VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, null,
                        "IoT endpoint без аутентификации"))
                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                    .severity(severity)
                    .riskScore(riskScore)
                    .title("IoT/Device Management эндпоинт без защиты")
                    .description(
                        "Обнаружен IoT/Device endpoint " + method + " " + path + " без аутентификации и ограничений доступа. " +
                        "Это позволяет выполнять операции управления устройствами, OTA-обновлений или телеметрии без контроля."
                    )
                    .endpoint(path)
                    .method(method)
                    .recommendation(
                        "Для IoT эндпоинтов обязательно:\n" +
                        "• Уникальная аутентификация для каждого устройства\n" +
                        "• Использование сертификатов/максимально строгих токенов\n" +
                        "• Ограничения на OTA/firmware операции\n" +
                        "• Логи и мониторинг необычной телеметрии"
                    )
                    .owaspCategory("IoT Security (OWASP IoT Top 10)")
                    .evidence("Индикаторы IoT: " + String.join(", ", indicatorHits))
                    .confidence(ConfidenceCalculator.calculateConfidence(temp, op, false, true))
                    .priority(ConfidenceCalculator.calculatePriority(temp,
                        ConfidenceCalculator.calculateConfidence(temp, op, false, true)))
                    .build());
            }
        }
        
        if (op.getParameters() == null) return;
        
        // ИСПОЛЬЗУЕМ SmartAnalyzer для контекста!
        int riskScore = SmartAnalyzer.calculateRiskScore(
            path, method, op, openAPI);
        Severity baseSeverity = SmartAnalyzer.severityFromRiskScore(riskScore);
        
        for (io.swagger.v3.oas.models.parameters.Parameter param : op.getParameters()) {
            if (EnhancedRules.isIoTRisk(param)) {
                // IoT почти всегда CRITICAL, но используем SmartAnalyzer для контекста
                Severity severity = (baseSeverity == Severity.CRITICAL || riskScore > 100) ? 
                    Severity.CRITICAL : Severity.CRITICAL; // IoT всегда критично
                
                Vulnerability tempVuln = Vulnerability.builder()
                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                    .severity(severity)
                    .riskScore(riskScore)
                    .build();
                
                vulnerabilities.add(Vulnerability.builder()
                    .id(VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, param.getName(),
                        "IoT device management security risk"))
                                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                                .severity(severity)
                                .riskScore(riskScore)
                                .title("IoT Device Security риск")
                                .description("IoT параметр '" + param.getName() + "' связан с устройствами!\n\n" +
                                    "Критичные риски IoT:\n" +
                                    "• Firmware update без signature → malware\n" +
                                    "• Device provisioning без auth → захват\n" +
                                    "• MQTT без TLS → перехват команд\n" +
                                    "• Weak device credentials")
                                .endpoint(path)
                                .method(method)
                                .recommendation(
                                    "IoT Security:\n\n" +
                                    "1. Firmware updates:\n" +
                                    "   - Digital signature (RSA/ECC)\n" +
                                    "   - Rollback protection\n" +
                                    "   - Secure boot\n" +
                                    "2. Device provisioning:\n" +
                                    "   - Unique credentials per device\n" +
                                    "   - Certificate-based auth\n" +
                                    "3. MQTT:\n" +
                                    "   - TLS 1.3\n" +
                                    "   - Client certificates\n" +
                                    "4. Rate limiting (защита от ботнетов)"
                                )
                                .owaspCategory("IoT Security (OWASP IoT Top 10)")
                                .evidence("IoT параметр: " + param.getName())
                                .confidence(ConfidenceCalculator.calculateConfidence(
                                    tempVuln, op, false, true))
                                .priority(ConfidenceCalculator.calculatePriority(
                                    tempVuln,
                                    ConfidenceCalculator.calculateConfidence(tempVuln, op, false, true)))
                                .build());
            }
        }
    }
    
    private List<Vulnerability> checkOpenBanking(OpenAPI openAPI, OpenAPIParser parser) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) return vulnerabilities;
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // Перебираем операции с их методами
            if (pathItem.getGet() != null) {
                checkOpenBankingOperation(path, "GET", pathItem.getGet(), openAPI, parser, vulnerabilities);
            }
            if (pathItem.getPost() != null) {
                checkOpenBankingOperation(path, "POST", pathItem.getPost(), openAPI, parser, vulnerabilities);
            }
            if (pathItem.getPut() != null) {
                checkOpenBankingOperation(path, "PUT", pathItem.getPut(), openAPI, parser, vulnerabilities);
            }
            if (pathItem.getDelete() != null) {
                checkOpenBankingOperation(path, "DELETE", pathItem.getDelete(), openAPI, parser, vulnerabilities);
            }
            if (pathItem.getPatch() != null) {
                checkOpenBankingOperation(path, "PATCH", pathItem.getPatch(), openAPI, parser, vulnerabilities);
            }
        }
        
        return vulnerabilities;
    }
    
    private void checkOpenBankingOperation(String path, String method, Operation op, OpenAPI openAPI, OpenAPIParser parser, List<Vulnerability> vulnerabilities) {
        if (op == null) return;
        
        // ИСПОЛЬЗУЕМ SmartAnalyzer для контекста!
        int riskScore = SmartAnalyzer.calculateRiskScore(
            path, method, op, openAPI);
        Severity baseSeverity = SmartAnalyzer.severityFromRiskScore(riskScore);
        
        Set<String> samples = collectOperationSamples(op);
        List<String> indicatorHits = new ArrayList<>(findTokens(samples,
            "openbanking", "open banking", "psd2", "xs2a", "aisp", "pisp",
            "consent", "permissions", "funds confirmation", "funds-confirmation",
            "account-access", "bank_token", "x-consent-id", "redirect-uri", "tpp", "account-consents",
            "sbp", "fast payment", "fps", "sbbol", "miraccept", "mir accept", "3ds",
            "x-psu-id", "x-psu-ip-address", "x-psu-corporate-id", "x-tpp-signature-certificate",
            "device-binding", "trusted device", "esid", "esia", "smev", "gosuslugi", "qseal", "qcert"));
        
        if (op.getParameters() != null) {
            for (io.swagger.v3.oas.models.parameters.Parameter param : op.getParameters()) {
                if (EnhancedRules.isOpenBankingRisk(param)) {
                    indicatorHits.add("param:" + param.getName());
                }
            }
        }
        
        if (indicatorHits.isEmpty()) {
            return;
        }
        
        boolean requiresAuth = parser != null && parser.requiresAuthentication(op);
        boolean hasAccessControl = AccessControlHeuristics.hasExplicitAccessControl(op, path, openAPI);
        boolean hasConsentEvidence = AccessControlHeuristics.hasConsentEvidence(op, openAPI);
        
        boolean insufficientProtection = !requiresAuth || (!hasAccessControl && !hasConsentEvidence);
        if (!insufficientProtection) {
            return;
        }
        
        Severity severity;
        if (!requiresAuth) {
            severity = Severity.CRITICAL;
        } else {
            severity = (baseSeverity == Severity.CRITICAL || riskScore > 120) ? Severity.CRITICAL : Severity.HIGH;
        }
        
        Vulnerability tempVuln = Vulnerability.builder()
            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
            .severity(severity)
            .riskScore(riskScore)
            .build();
        
        vulnerabilities.add(Vulnerability.builder()
            .id(VulnerabilityIdGenerator.generateId(
                VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, null,
                "Open Banking/PSD2 compliance risk"))
            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
            .severity(severity)
            .riskScore(riskScore)
            .title("Open Banking/PSD2 безопасность настроена некорректно")
            .description(
                "Эндпоинт " + method + " " + path + " содержит Open Banking/PSD2 сущности (" +
                    String.join(", ", indicatorHits) + "), но не обеспечивает необходимые меры защиты.\n" +
                    "PSD2 требует Strong Customer Authentication, динамическую привязку транзакций и управление consent."
            )
            .endpoint(path)
            .method(method)
            .recommendation(
                "Проверьте соответствие PSD2:\n" +
                "• SCA (двухфакторная аутентификация)\n" +
                "• Dynamic linking (сумма + получатель)\n" +
                "• eIDAS/qualified certificates\n" +
                "• Consent management и revoke\n" +
                "• Ограничения на доступ TPP (AISP/PISP)\n"
            )
            .owaspCategory("PSD2 Compliance (EU Directive 2015/2366)")
            .evidence("Индикаторы Open Banking: " + String.join(", ", indicatorHits))
            .confidence(ConfidenceCalculator.calculateConfidence(
                tempVuln, op, false, true))
            .priority(ConfidenceCalculator.calculatePriority(
                tempVuln,
                ConfidenceCalculator.calculateConfidence(tempVuln, op, false, true)))
            .build());
    }
    
    private boolean hasGlobalStrongAuthorization(OpenAPI openAPI) {
        if (openAPI == null) {
            return false;
        }
        if (openAPI.getSecurity() != null) {
            for (io.swagger.v3.oas.models.security.SecurityRequirement requirement : openAPI.getSecurity()) {
                for (String schemeName : requirement.keySet()) {
                    if (AccessControlHeuristics.hasStrongAuthorization(openAPI, schemeName)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean hasGlobalConsentEvidence(OpenAPI openAPI) {
        if (openAPI == null || openAPI.getPaths() == null) {
            return false;
        }
        return openAPI.getPaths().values().stream()
            .filter(Objects::nonNull)
            .flatMap(pathItem -> getOperationsWithMethods(pathItem).values().stream())
            .filter(Objects::nonNull)
            .anyMatch(op -> AccessControlHeuristics.hasConsentEvidence(op, openAPI));
    }

    private Severity determineHttpSeverity(ContextAnalyzer.APIContext context,
                                           boolean strongAccess,
                                           boolean consentContext) {
        Severity severity;
        if (context == ContextAnalyzer.APIContext.BANKING ||
            context == ContextAnalyzer.APIContext.GOVERNMENT ||
            context == ContextAnalyzer.APIContext.HEALTHCARE) {
            severity = Severity.CRITICAL;
        } else {
            severity = Severity.HIGH;
        }
        if (strongAccess) {
            severity = downgradeSeverity(severity);
        }
        if (consentContext) {
            severity = downgradeSeverity(severity);
        }
        return severity;
    }

    private int calculateHttpRiskScore(Severity severity,
                                       boolean strongAccess,
                                       boolean consentContext) {
        int base = switch (severity) {
            case CRITICAL -> 95;
            case HIGH -> 80;
            case MEDIUM -> 60;
            default -> 40;
        };
        if (strongAccess) {
            base -= 10;
        }
        if (consentContext) {
            base -= 5;
        }
        return Math.max(0, base);
    }

    private String buildHttpEvidence(String url,
                                     int riskScore,
                                     boolean strongAccess,
                                     boolean consentContext) {
        StringBuilder builder = new StringBuilder("Server URL: ").append(url)
            .append(". Risk Score: ").append(riskScore);
        if (strongAccess) {
            builder.append(". Обнаружены глобальные схемы сильной авторизации.");
        }
        if (consentContext) {
            builder.append(" Банковский контекст, проверьте обязательства по PSD2/ГОСТ.");
        }
        return builder.toString();
    }

    private Severity downgradeSeverity(Severity current) {
        return switch (current) {
            case CRITICAL -> Severity.HIGH;
            case HIGH -> Severity.MEDIUM;
            case MEDIUM -> Severity.LOW;
            default -> current;
        };
    }
}

