package com.vtb.scanner.scanners;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.deep.*;
import com.vtb.scanner.heuristics.EnhancedRules;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.servers.Server;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

import com.vtb.scanner.util.AccessControlHeuristics;

/**
 * API8:2023 - Security Misconfiguration
 * Проверяет проблемы конфигурации: HTTP, CORS, verbose errors
 */
@Slf4j
public class MisconfigScanner implements VulnerabilityScanner {
    
    private final String targetUrl;
    
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
        com.vtb.scanner.semantic.ContextAnalyzer.APIContext context = 
            com.vtb.scanner.semantic.ContextAnalyzer.detectContext(openAPI);
        
        // 1. Проверка HTTP vs HTTPS
        vulnerabilities.addAll(checkTransportSecurity(openAPI));
        
        // 2. Проверка CORS
        vulnerabilities.addAll(checkCORS(openAPI));
        
        // 3. Проверка verbose errors
        vulnerabilities.addAll(checkErrorHandling(openAPI));
        
        // 4. НОВОЕ: Security Headers (HSTS, CSP, X-Frame, etc.)
        vulnerabilities.addAll(SecurityHeadersChecker.checkSecurityHeaders(openAPI));
        
        // 5. НОВОЕ: Cookie Security (HttpOnly, Secure, SameSite)
        vulnerabilities.addAll(CookieSecurityChecker.checkCookies(openAPI));
        
        // 6. НОВОЕ: OAuth 2.0 Flows
        vulnerabilities.addAll(OAuthFlowChecker.checkOAuthFlows(openAPI));
        
        // 7. НОВОЕ: JWT токены
        vulnerabilities.addAll(JWTAnalyzer.analyzeJWT(openAPI));
        
        // 8. НОВОЕ: File Uploads
        vulnerabilities.addAll(FileUploadChecker.checkFileUploads(openAPI));
        
        // 9. НОВЕЙШЕЕ: GraphQL Security
        vulnerabilities.addAll(checkGraphQL(openAPI));
        
        // 10. НОВЕЙШЕЕ: IoT/Device Management
        vulnerabilities.addAll(checkIoT(openAPI));
        
        // 11. НОВЕЙШЕЕ: Open Banking/PSD2
        vulnerabilities.addAll(checkOpenBanking(openAPI));
        
        log.info("Misconfiguration Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkTransportSecurity(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getServers() == null || openAPI.getServers().isEmpty()) {
            return vulnerabilities;
        }
        
        // Определяем контекст для адаптации severity
        com.vtb.scanner.semantic.ContextAnalyzer.APIContext context = 
            com.vtb.scanner.semantic.ContextAnalyzer.detectContext(openAPI);
        
        for (Server server : openAPI.getServers()) {
            if (server.getUrl() != null && server.getUrl().startsWith("http://")) {
                // КОНТЕКСТ: для банков/госструктур HTTP = CRITICAL!
                Severity severity = (context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.BANKING ||
                                    context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.GOVERNMENT ||
                                    context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.HEALTHCARE) 
                                    ? Severity.CRITICAL : Severity.HIGH;
                
                Vulnerability tempVuln = Vulnerability.builder()
                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                    .severity(severity)
                    .build();
                
                vulnerabilities.add(Vulnerability.builder()
                    .id("MISC-HTTP")
                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                    .severity(severity)
                    .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                        tempVuln, null, false, true)) // evidence=true (точно HTTP)
                    .priority(com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                        tempVuln, 100))
                    .title("Использование незащищенного HTTP")
                    .description(String.format(
                        "Server URL использует HTTP вместо HTTPS: %s. " +
                        "Данные передаются в открытом виде, возможен перехват (MITM).",
                        server.getUrl()
                    ))
                    .endpoint("N/A")
                    .method("N/A")
                    .recommendation(
                        "Используйте HTTPS для всех API. " +
                        "Настройте TLS 1.2+ с современными cipher suites. " +
                        "Для России: поддержка ГОСТ TLS."
                    )
                    .owaspCategory("API8:2023 - Security Misconfiguration")
                    .evidence("Server URL: " + server.getUrl())
                    .build());
            }
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkCORS(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // Проверяем наличие OPTIONS (CORS preflight)
            if (pathItem.getOptions() != null) {
                Operation options = pathItem.getOptions();
                
                String desc = options.getDescription() != null ? options.getDescription().toLowerCase() : "";
                boolean hasCorsDesc = desc.contains("cors") || 
                                     desc.contains("cross-origin") ||
                                     desc.contains("access-control");
                
                if (!hasCorsDesc) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.CORS_MISCONFIGURATION, path, "OPTIONS", null,
                            "CORS policy not documented"))
                        .type(VulnerabilityType.CORS_MISCONFIGURATION)
                        .severity(Severity.LOW)
                        .title("CORS политика не документирована")
                        .description(String.format(
                            "Эндпоинт %s имеет OPTIONS метод (CORS preflight), " +
                            "но CORS политика не описана",
                            path
                        ))
                        .endpoint(path)
                        .method("OPTIONS")
                        .recommendation(
                            "Четко опишите CORS политику:\n" +
                            "- Allowed origins (не используйте *)\n" +
                            "- Allowed methods\n" +
                            "- Allowed headers\n" +
                            "- Credentials policy"
                        )
                        .owaspCategory("API8:2023 - Security Misconfiguration")
                        .evidence("OPTIONS метод без описания CORS")
                        .build());
                }
            }
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkErrorHandling(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // Проверяем все методы на verbose errors
            List<Operation> operations = new ArrayList<>();
            if (pathItem.getGet() != null) operations.add(pathItem.getGet());
            if (pathItem.getPost() != null) operations.add(pathItem.getPost());
            if (pathItem.getPut() != null) operations.add(pathItem.getPut());
            if (pathItem.getDelete() != null) operations.add(pathItem.getDelete());
            
            for (Operation op : operations) {
                if (op.getResponses() == null) continue;
                
                // Проверяем 500 errors
                ApiResponse response500 = op.getResponses().get("500");
                if (response500 != null && response500.getDescription() != null) {
                    String desc = response500.getDescription().toLowerCase();
                    
                    if (desc.contains("stack trace") || 
                        desc.contains("exception") ||
                        desc.contains("error details") ||
                        desc.contains("debug")) {
                        
                        vulnerabilities.add(Vulnerability.builder()
                            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                                VulnerabilityType.SECURITY_MISCONFIGURATION, path, "N/A", null,
                                "Verbose error information leakage"))
                            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                            .severity(Severity.MEDIUM)
                            .title("Возможна утечка информации в ошибках")
                            .description(String.format(
                                "Response 500 для %s может содержать детальную информацию об ошибках",
                                path
                            ))
                            .endpoint(path)
                            .method("N/A")
                            .recommendation(
                                "Не возвращайте stack traces и детали ошибок в production. " +
                                "Используйте generic error messages. " +
                                "Логируйте детали на сервере, не отправляйте клиенту."
                            )
                            .owaspCategory("API8:2023 - Security Misconfiguration")
                            .evidence("500 response: " + response500.getDescription())
                            .build());
                        break;
                    }
                }
            }
        }
        
        return vulnerabilities;
    }
    
    // ═══════════════════════════════════════════════════════════════
    // НОВЫЕ ПРОВЕРКИ ИЗ EnhancedRules
    // ═══════════════════════════════════════════════════════════════
    
    private List<Vulnerability> checkGraphQL(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) return vulnerabilities;
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // Проверяем GraphQL endpoints
            if (path.toLowerCase().contains("graphql") || 
                path.toLowerCase().contains("/graph")) {
                
                List<Operation> operations = getOperations(pathItem);
                for (Operation op : operations) {
                    if (op.getParameters() != null) {
                        // ИСПОЛЬЗУЕМ SmartAnalyzer для контекста!
                        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
                            path, "POST", op, openAPI);
                        Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
                        
                        for (io.swagger.v3.oas.models.parameters.Parameter param : op.getParameters()) {
                            if (EnhancedRules.isGraphQLRisk(param)) {
                                // УМНЫЙ расчёт: GraphQL обычно HIGH, но используем SmartAnalyzer
                                Severity severity = (baseSeverity == Severity.CRITICAL || riskScore > 120) ? 
                                    Severity.CRITICAL : Severity.HIGH;
                                
                                Vulnerability tempVuln = Vulnerability.builder()
                                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                                    .severity(severity)
                                    .riskScore(riskScore)
                                    .build();
                                
                                vulnerabilities.add(Vulnerability.builder()
                                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                                        VulnerabilityType.SECURITY_MISCONFIGURATION, path, "POST", param.getName(),
                                        "GraphQL security risk"))
                                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                                    .severity(severity)
                                    .riskScore(riskScore)
                                    .title("GraphQL Security риск: introspection/mutation")
                                    .description("GraphQL параметр '" + param.getName() + "' может:\n\n" +
                                        "• Introspection включен → раскрытие схемы\n" +
                                        "• Нет depth limiting → DoS\n" +
                                        "• Нет query complexity → CPU exhaustion\n" +
                                        "• Batch attacks (алиасы)")
                                    .endpoint(path)
                                    .method("POST")
                                    .recommendation(
                                        "GraphQL защита:\n\n" +
                                        "1. ОТКЛЮЧИТЕ introspection в production!\n" +
                                        "2. Depth limiting (max 5-7 уровней)\n" +
                                        "3. Query complexity analysis\n" +
                                        "4. Rate limiting по операциям\n" +
                                        "5. Disable unused mutations\n" +
                                        "6. Persistent queries (whitelist)"
                                    )
                                    .owaspCategory("API8:2023 - GraphQL Misconfiguration")
                                    .evidence("GraphQL параметр: " + param.getName())
                                    .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                                        tempVuln, op, false, true))
                                    .priority(com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                                        tempVuln, 
                                        com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(tempVuln, op, false, true)))
                                    .build());
                            }
                        }
                    }
                }
            }
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkIoT(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) return vulnerabilities;
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // Перебираем операции с их методами
            if (pathItem.getGet() != null) {
                checkIoTOperation(path, "GET", pathItem.getGet(), openAPI, vulnerabilities);
            }
            if (pathItem.getPost() != null) {
                checkIoTOperation(path, "POST", pathItem.getPost(), openAPI, vulnerabilities);
            }
            if (pathItem.getPut() != null) {
                checkIoTOperation(path, "PUT", pathItem.getPut(), openAPI, vulnerabilities);
            }
            if (pathItem.getDelete() != null) {
                checkIoTOperation(path, "DELETE", pathItem.getDelete(), openAPI, vulnerabilities);
            }
            if (pathItem.getPatch() != null) {
                checkIoTOperation(path, "PATCH", pathItem.getPatch(), openAPI, vulnerabilities);
            }
        }
        
        return vulnerabilities;
    }
    
    private void checkIoTOperation(String path, String method, Operation op, OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        if (op.getParameters() == null) return;
        
        // ИСПОЛЬЗУЕМ SmartAnalyzer для контекста!
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
            path, method, op, openAPI);
        Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
        
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
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
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
                                .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                                    tempVuln, op, false, true))
                                .priority(com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                                    tempVuln,
                                    com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(tempVuln, op, false, true)))
                                .build());
            }
        }
    }
    
    private List<Vulnerability> checkOpenBanking(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) return vulnerabilities;
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // Перебираем операции с их методами
            if (pathItem.getGet() != null) {
                checkOpenBankingOperation(path, "GET", pathItem.getGet(), openAPI, vulnerabilities);
            }
            if (pathItem.getPost() != null) {
                checkOpenBankingOperation(path, "POST", pathItem.getPost(), openAPI, vulnerabilities);
            }
            if (pathItem.getPut() != null) {
                checkOpenBankingOperation(path, "PUT", pathItem.getPut(), openAPI, vulnerabilities);
            }
            if (pathItem.getDelete() != null) {
                checkOpenBankingOperation(path, "DELETE", pathItem.getDelete(), openAPI, vulnerabilities);
            }
            if (pathItem.getPatch() != null) {
                checkOpenBankingOperation(path, "PATCH", pathItem.getPatch(), openAPI, vulnerabilities);
            }
        }
        
        return vulnerabilities;
    }
    
    private void checkOpenBankingOperation(String path, String method, Operation op, OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        if (op.getParameters() == null) return;
        
        // ИСПОЛЬЗУЕМ SmartAnalyzer для контекста!
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
            path, method, op, openAPI);
        Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
        
        for (io.swagger.v3.oas.models.parameters.Parameter param : op.getParameters()) {
            if (EnhancedRules.isOpenBankingRisk(param)) {
                if (AccessControlHeuristics.hasExplicitAccessControl(op, path)) {
                    continue;
                }
                // Open Banking - используем SmartAnalyzer (финансы = выше severity)
                Severity severity = (baseSeverity == Severity.CRITICAL || riskScore > 120) ? 
                    Severity.CRITICAL : Severity.HIGH;
                
                Vulnerability tempVuln = Vulnerability.builder()
                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                    .severity(severity)
                    .riskScore(riskScore)
                    .build();
                
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, param.getName(),
                        "Open Banking/PSD2 compliance risk"))
                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                    .severity(severity)
                    .riskScore(riskScore)
                    .title("Open Banking/PSD2 Security риск")
                    .description("Open Banking параметр '" + param.getName() + "'!\n\n" +
                        "PSD2 требования:\n" +
                        "• Strong Customer Authentication (SCA)\n" +
                        "• Dynamic linking (сумма + получатель)\n" +
                        "• eIDAS certificates\n" +
                        "• Transaction monitoring\n\n" +
                        "Критично для EU финансов!")
                    .endpoint(path)
                    .method(method)
                    .recommendation(
                        "PSD2/Open Banking:\n\n" +
                        "1. SCA обязателен:\n" +
                        "   - 2FA (что знаю + что имею)\n" +
                        "   - Dynamic linking\n" +
                        "2. eIDAS сертификаты:\n" +
                        "   - Qualified certificates\n" +
                        "   - QTSP providers\n" +
                        "3. Consent management:\n" +
                        "   - Explicit consent\n" +
                        "   - Revocation mechanism\n" +
                        "4. Berlin Group/STET standard"
                    )
                    .owaspCategory("PSD2 Compliance (EU Directive 2015/2366)")
                    .evidence("Open Banking параметр: " + param.getName())
                    .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                        tempVuln, op, false, true))
                    .priority(com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                        tempVuln,
                        com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(tempVuln, op, false, true)))
                    .build());
            }
        }
    }
    
    private List<Operation> getOperations(PathItem pathItem) {
        List<Operation> operations = new ArrayList<>();
        if (pathItem.getGet() != null) operations.add(pathItem.getGet());
        if (pathItem.getPost() != null) operations.add(pathItem.getPost());
        if (pathItem.getPut() != null) operations.add(pathItem.getPut());
        if (pathItem.getDelete() != null) operations.add(pathItem.getDelete());
        if (pathItem.getPatch() != null) operations.add(pathItem.getPatch());
        return operations;
    }
}

