package com.vtb.scanner.scanners;

import com.vtb.scanner.core.OpenAPIParser;
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

/**
 * API5:2023 - Broken Function Level Authorization (BFLA)
 * Проверяет права доступа на уровне функций/ролей
 */
@Slf4j
public class BFLAScanner implements VulnerabilityScanner {
    
    private final String targetUrl;
    private final com.vtb.scanner.config.ScannerConfig config;
    private final List<String> adminPaths;
    
    // Критичные HTTP методы (это константа, не меняется)
    private static final Set<String> CRITICAL_METHODS = Set.of("DELETE", "PUT", "PATCH");
    private static final Set<String> AUTH_PARAM_NAMES = Set.of(
        "client_id", "clientid", "client-secret", "client_secret",
        "clientsecret", "grant_type", "granttype", "clienttoken", "bank_token"
    );
    
    public BFLAScanner(String targetUrl) {
        this.targetUrl = targetUrl;
        
        // Используем конфигурацию вместо хардкода!
        this.config = com.vtb.scanner.config.ScannerConfig.load();
        
        // Админ пути из конфига
        this.adminPaths = new ArrayList<>();
        if (config.getSensitivePaths() != null && config.getSensitivePaths().get("admin") != null) {
            this.adminPaths.addAll(config.getSensitivePaths().get("admin"));
        }
    }
    
    @Override
    public List<Vulnerability> scan(OpenAPI openAPI, OpenAPIParser parser) {
        log.info("Запуск BFLA Scanner (API5:2023)...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            boolean isAdminPath = isAdministrativePath(path);
            
            // Проверяем все методы
            if (pathItem.getGet() != null) {
                vulnerabilities.addAll(checkBFLA(path, "GET", pathItem.getGet(), isAdminPath, parser, openAPI));
            }
            if (pathItem.getPost() != null) {
                vulnerabilities.addAll(checkBFLA(path, "POST", pathItem.getPost(), isAdminPath, parser, openAPI));
            }
            if (pathItem.getPut() != null) {
                vulnerabilities.addAll(checkBFLA(path, "PUT", pathItem.getPut(), isAdminPath, parser, openAPI));
            }
            if (pathItem.getDelete() != null) {
                vulnerabilities.addAll(checkBFLA(path, "DELETE", pathItem.getDelete(), isAdminPath, parser, openAPI));
            }
            if (pathItem.getPatch() != null) {
                vulnerabilities.addAll(checkBFLA(path, "PATCH", pathItem.getPatch(), isAdminPath, parser, openAPI));
            }
        }
        
        log.info("BFLA Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkBFLA(String path, String method, Operation operation,
                                          boolean isAdminPath, OpenAPIParser parser, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (isAuthenticationEndpoint(path, operation)) {
            return vulnerabilities;
        }

        // ИСПОЛЬЗУЕМ SmartAnalyzer для контекста!
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
            path, method, operation, openAPI);
        Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
        
        // СЕМАНТИЧЕСКИЙ АНАЛИЗ - определяем тип операции!
        com.vtb.scanner.semantic.OperationClassifier.OperationType opType = 
            com.vtb.scanner.semantic.OperationClassifier.classify(path, method, operation);
        
        boolean isAdminOperation = (opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.ADMIN_ACTION ||
                                   opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.USER_MANAGEMENT ||
                                   opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.ROLE_MANAGEMENT);
        
        boolean requiresAuth = parser.requiresAuthentication(operation);
        boolean hasRoleCheck = hasRoleBasedAuth(operation, path);
        boolean isCriticalOperation = isCriticalOperation(path, method, operation);
        
        // 1. Административный путь без аутентификации
        if (isAdminPath && !requiresAuth) {
            // УМНЫЙ расчёт: админ без auth = гарантированно CRITICAL, но используем SmartAnalyzer для контекста
            Severity severity = (baseSeverity == Severity.CRITICAL || riskScore > 100 || isAdminOperation) ? 
                Severity.CRITICAL : Severity.HIGH;
            
            // ДИНАМИЧЕСКИЙ расчет!
            Vulnerability tempVuln = Vulnerability.builder()
                .type(VulnerabilityType.BFLA)
                .severity(severity)
                .riskScore(riskScore)
                .build();
            
            int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                tempVuln, operation, false, true); // hasEvidence=true (админ путь найден!)
            
            // Если админская операция - повышаем
            if (isAdminOperation) {
                confidence = Math.min(100, confidence + 15);
            }
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Admin endpoint without proper authorization"))
                .type(VulnerabilityType.BFLA)
                .severity(severity)
                .riskScore(riskScore)
                .confidence(confidence)
                .priority(1) // КРИТИЧНО - исправить немедленно!
                .impactLevel("PRIVILEGE_ESCALATION: Админ доступ")
                .title("Административный функционал без аутентификации")
                .description(String.format(
                    "Эндпоинт %s %s является административным, но не требует аутентификации",
                    method, path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Добавьте аутентификацию и проверку роли администратора. " +
                    "Используйте RBAC (Role-Based Access Control)."
                )
                .owaspCategory("API5:2023 - Broken Function Level Authorization")
                .evidence("Административный путь без security. Risk Score: " + riskScore)
                .build());
        }
        
        // 2. Административный путь без проверки ролей
        if (isAdminPath && requiresAuth && !hasRoleCheck) {
            // Используем SmartAnalyzer, но повышаем для админских путей
            Severity severity = switch(baseSeverity) {
                case CRITICAL, HIGH -> Severity.HIGH;
                case MEDIUM -> Severity.HIGH;
                default -> Severity.MEDIUM;
            };
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Role-based endpoint without authorization check"))
                .type(VulnerabilityType.BFLA)
                .severity(severity)
                .riskScore(riskScore)
                .title("Нет проверки роли для административного функционала")
                .description(String.format(
                    "Эндпоинт %s %s требует аутентификации, но не проверяет роль администратора",
                    method, path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Добавьте проверку роли/прав доступа. " +
                    "Обычный пользователь не должен иметь доступ к admin функциям."
                )
                .owaspCategory("API5:2023 - Broken Function Level Authorization")
                .evidence("Нет упоминания ролей в security или description")
                .build());
        }
        
        // 3. Критичные операции без проверки прав
        if (isCriticalOperation && requiresAuth && !hasRoleCheck) {
            // Используем SmartAnalyzer для критичных операций
            Severity severity = (baseSeverity == Severity.CRITICAL || riskScore > 100) ? 
                Severity.CRITICAL : Severity.HIGH;
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Critical operation without authorization"))
                .type(VulnerabilityType.BFLA)
                .severity(severity)
                .riskScore(riskScore)
                .title("Критичная операция без проверки прав")
                .description(String.format(
                    "Операция %s %s выполняет критичное действие без проверки прав доступа",
                    method, path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Добавьте проверку прав на выполнение этой операции. " +
                    "Не все аутентифицированные пользователи должны иметь доступ."
                )
                .owaspCategory("API5:2023 - Broken Function Level Authorization")
                .evidence("Критичная операция без role-based auth")
                .build());
        }
        
        // 4. DELETE/PUT без доп. авторизации
        if (CRITICAL_METHODS.contains(method) && !requiresAuth) {
            // Критичные методы без auth - используем SmartAnalyzer
            Severity severity = (baseSeverity == Severity.CRITICAL || riskScore > 100) ? 
                Severity.CRITICAL : Severity.HIGH;
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Dangerous HTTP method without authorization"))
                .type(VulnerabilityType.BFLA)
                .severity(severity)
                .riskScore(riskScore)
                .title(method + " метод без авторизации")
                .description(String.format(
                    "Метод %s для %s не требует авторизации",
                    method, path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Методы DELETE/PUT/PATCH должны требовать строгую авторизацию"
                )
                .owaspCategory("API5:2023 - Broken Function Level Authorization")
                .evidence(method + " без security")
                .build());
        }
        
        return vulnerabilities;
    }
    
    private boolean isAdministrativePath(String path) {
        String lowerPath = path.toLowerCase();
        // Используем конфиг!
        return adminPaths.stream().anyMatch(lowerPath::contains);
    }
    
    private boolean isCriticalOperation(String path, String method, Operation operation) {
        // Проверяем метод
        if (CRITICAL_METHODS.contains(method)) {
            return true;
        }

        if ("GET".equalsIgnoreCase(method)) {
            return false;
        }
        
        // Проверяем summary и description на критичные операции
        String text = (operation.getSummary() != null ? operation.getSummary() : "") +
                     (operation.getDescription() != null ? operation.getDescription() : "");
        String lowerText = text.toLowerCase();
        
        // Ищем админские операции
        String[] adminOps = {"delete", "remove", "ban", "suspend", "disable",
                            "promote", "grant", "revoke", "approve", "reject"};
        return Arrays.stream(adminOps).anyMatch(lowerText::contains);
    }
    
    private boolean hasRoleBasedAuth(Operation operation, String path) {
        // Проверяем упоминание ролей в описании
        String desc = (operation.getDescription() != null ? operation.getDescription() : "") +
                     (operation.getSummary() != null ? operation.getSummary() : "");
        String lowerDesc = desc.toLowerCase();
        
        if (lowerDesc.contains("role") ||
            lowerDesc.contains("permission") ||
            lowerDesc.contains("admin only") ||
            lowerDesc.contains("administrator") ||
            lowerDesc.contains("rbac") ||
            lowerDesc.contains("scope")) {
            return true;
        }

        // OAuth scopes в security requirements
        if (operation.getSecurity() != null) {
            for (io.swagger.v3.oas.models.security.SecurityRequirement req : operation.getSecurity()) {
                for (List<String> scopes : req.values()) {
                    if (scopes != null && !scopes.isEmpty()) {
                        return true;
                    }
                }
            }
        }

        // Consents / tokens / дополнительная авторизация
        return AccessControlHeuristics.hasExplicitAccessControl(operation, path);
    }

    private boolean isAuthenticationEndpoint(String path, Operation operation) {
        String lowerPath = path != null ? path.toLowerCase(Locale.ROOT) : "";
        if (lowerPath.contains("/auth/") || lowerPath.contains("token")) {
            return true;
        }

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

        if (operation != null && operation.getParameters() != null) {
            for (Parameter parameter : operation.getParameters()) {
                if (parameter.getName() == null) continue;
                String name = parameter.getName().toLowerCase(Locale.ROOT);
                String canonical = name.replaceAll("[^a-z0-9]", "");
                if (AUTH_PARAM_NAMES.contains(name) || AUTH_PARAM_NAMES.contains(canonical)) {
                    return true;
                }
            }
        }

        return combined.contains("token") || combined.contains("oauth") || combined.contains("authentication");
    }
}

