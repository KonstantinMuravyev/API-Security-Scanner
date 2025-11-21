package com.vtb.scanner.scanners;

import com.vtb.scanner.analysis.SchemaConstraintAnalyzer;
import com.vtb.scanner.analysis.SchemaConstraintAnalyzer.SchemaConstraints;
import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.util.AccessControlHeuristics;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.media.Schema;
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
        log.info("Запуск BFLA Scanner (API5:2023) для {}...", targetUrl);
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        SchemaConstraintAnalyzer constraintAnalyzer = new SchemaConstraintAnalyzer(openAPI);

        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            boolean isAdminPath = isAdministrativePath(path);
            
            // Проверяем все методы
            if (pathItem.getGet() != null) {
                vulnerabilities.addAll(checkBFLA(path, "GET", pathItem.getGet(), isAdminPath, parser, openAPI,
                    pathItem.getParameters(), constraintAnalyzer));
            }
            if (pathItem.getPost() != null) {
                vulnerabilities.addAll(checkBFLA(path, "POST", pathItem.getPost(), isAdminPath, parser, openAPI,
                    pathItem.getParameters(), constraintAnalyzer));
            }
            if (pathItem.getPut() != null) {
                vulnerabilities.addAll(checkBFLA(path, "PUT", pathItem.getPut(), isAdminPath, parser, openAPI,
                    pathItem.getParameters(), constraintAnalyzer));
            }
            if (pathItem.getDelete() != null) {
                vulnerabilities.addAll(checkBFLA(path, "DELETE", pathItem.getDelete(), isAdminPath, parser, openAPI,
                    pathItem.getParameters(), constraintAnalyzer));
            }
            if (pathItem.getPatch() != null) {
                vulnerabilities.addAll(checkBFLA(path, "PATCH", pathItem.getPatch(), isAdminPath, parser, openAPI,
                    pathItem.getParameters(), constraintAnalyzer));
            }
        }
        
        log.info("BFLA Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private boolean isAdministrativePath(String path) {
        if (path == null) {
            return false;
        }
        String lower = path.toLowerCase(Locale.ROOT);
        if (adminPaths != null && adminPaths.stream().anyMatch(lower::contains)) {
            return true;
        }
        return lower.contains("/admin") ||
            lower.contains("/administrator") ||
            lower.contains("/management") ||
            lower.contains("/console") ||
            lower.contains("/backoffice");
    }
    
    private List<Vulnerability> checkBFLA(String path,
                                          String method,
                                          Operation operation,
                                          boolean isAdminPath,
                                          OpenAPIParser parser,
                                          OpenAPI openAPI,
                                          List<Parameter> inheritedParameters,
                                          SchemaConstraintAnalyzer constraintAnalyzer) {
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

        String lowerPath = path != null ? path.toLowerCase(Locale.ROOT) : "";
        String combinedText = combineOperationText(operation);
        boolean isTelecomOperation = isTelecomOperation(lowerPath, combinedText);
        boolean isTelecomCritical = isTelecomCriticalOperation(lowerPath, combinedText);
        boolean isConnectedCarOperation = isConnectedCarOperation(lowerPath, combinedText);
        boolean isRemoteVehicleControl = isRemoteVehicleControl(lowerPath, combinedText);
        com.vtb.scanner.semantic.ContextAnalyzer.APIContext apiContext =
            com.vtb.scanner.semantic.ContextAnalyzer.detectContext(openAPI);
        
        List<Parameter> allParameters = combineParameters(inheritedParameters, operation);

        boolean requiresAuth = parser.requiresAuthentication(operation);
        boolean hasRoleCheck = hasRoleBasedAuth(operation, path, openAPI);
        boolean hasExplicitAccess = AccessControlHeuristics.hasExplicitAccessControl(operation, path, openAPI);
        boolean hasConsentEvidence = AccessControlHeuristics.hasConsentEvidence(operation, openAPI);
        boolean hasStrongAuthorization = AccessControlHeuristics.hasStrongAuthorization(operation, openAPI);
        boolean isOpenBankingOperation = AccessControlHeuristics.isOpenBankingOperation(path, operation, openAPI);
        boolean skipDueToStrongBankingControls = !isAdminPath && isOpenBankingOperation &&
            (hasStrongAuthorization || hasConsentEvidence || hasExplicitAccess);
        boolean isCriticalOperation = isCriticalOperation(path, method, operation);
        
        List<PrivilegeField> privilegeFields = collectPrivilegeFields(allParameters, operation, constraintAnalyzer);
        boolean schemaStrongGuard = !privilegeFields.isEmpty() && privilegeFields.stream().allMatch(PrivilegeField::isGuarded);
        boolean schemaUnguarded = privilegeFields.stream().anyMatch(field -> !field.isGuarded());
        List<String> privilegeSchemaNotes = buildPrivilegeEvidence(privilegeFields);

        boolean strongAccessControls = hasStrongAuthorization || hasExplicitAccess;
        boolean consentBankingContext = (hasConsentEvidence || isOpenBankingOperation) &&
            apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.BANKING;
        if (schemaStrongGuard) {
            strongAccessControls = true;
        }

        if (isAdminPath && !requiresAuth) {
            // УМНЫЙ расчёт: админ без auth = гарантированно CRITICAL, но используем SmartAnalyzer для контекста
            Severity severity = (baseSeverity == Severity.CRITICAL || riskScore > 100 || isAdminOperation) ? 
                Severity.CRITICAL : Severity.HIGH;
            if (schemaStrongGuard) {
                severity = downgradeSeverity(severity);
            }
            Severity finalSeverity = applySeverityModifiers(severity, strongAccessControls, consentBankingContext, Severity.HIGH);
            int adjustedRisk = adjustRiskScoreForControls(riskScore, strongAccessControls, consentBankingContext);
            if (schemaStrongGuard) {
                adjustedRisk = Math.max(0, adjustedRisk - 10);
            } else if (schemaUnguarded) {
                adjustedRisk = Math.min(150, adjustedRisk + 8);
            }
            
            // ДИНАМИЧЕСКИЙ расчет!
            Vulnerability tempVuln = Vulnerability.builder()
                .type(VulnerabilityType.BFLA)
                .severity(finalSeverity)
                .riskScore(adjustedRisk)
                .build();
            
            int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                tempVuln, operation, false, true); // hasEvidence=true (админ путь найден!)
            
            // Если админская операция - повышаем
            if (isAdminOperation) {
                confidence = Math.min(100, confidence + 15);
            }
            if (schemaStrongGuard) {
                confidence = Math.max(30, confidence - 10);
            } else if (schemaUnguarded) {
                confidence = Math.min(100, confidence + 10);
            }
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Admin endpoint without proper authorization"))
                .type(VulnerabilityType.BFLA)
                .severity(finalSeverity)
                .riskScore(adjustedRisk)
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
                .evidence(withSchemaEvidence(
                    buildControlEvidence("Административный путь без security", riskScore, adjustedRisk,
                        strongAccessControls, consentBankingContext),
                    privilegeSchemaNotes))
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
            if (schemaStrongGuard) {
                severity = downgradeSeverity(severity);
            }
            Severity finalSeverity = applySeverityModifiers(severity, strongAccessControls, consentBankingContext, Severity.MEDIUM);
            int adjustedRisk = adjustRiskScoreForControls(riskScore, strongAccessControls, consentBankingContext);
            if (schemaStrongGuard) {
                adjustedRisk = Math.max(0, adjustedRisk - 10);
            } else if (schemaUnguarded) {
                adjustedRisk = Math.min(150, adjustedRisk + 5);
            }
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Role-based endpoint without authorization check"))
                .type(VulnerabilityType.BFLA)
                .severity(finalSeverity)
                .riskScore(adjustedRisk)
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
                .evidence(withSchemaEvidence(
                    buildControlEvidence("Нет упоминания ролей в security или description",
                        riskScore, adjustedRisk, strongAccessControls, consentBankingContext),
                    privilegeSchemaNotes))
                .build());
        }
        
        // 3. Критичные операции без проверки прав
        if (isCriticalOperation && requiresAuth && !hasRoleCheck && !skipDueToStrongBankingControls) {
            // Используем SmartAnalyzer для критичных операций
            Severity severity = (baseSeverity == Severity.CRITICAL || riskScore > 100) ? 
                Severity.CRITICAL : Severity.HIGH;
            if (schemaStrongGuard) {
                severity = downgradeSeverity(severity);
            }
            Severity finalSeverity = applySeverityModifiers(severity, strongAccessControls, consentBankingContext, Severity.HIGH);
            int adjustedRisk = adjustRiskScoreForControls(riskScore, strongAccessControls, consentBankingContext);
            if (schemaStrongGuard) {
                adjustedRisk = Math.max(0, adjustedRisk - 8);
            } else if (schemaUnguarded) {
                adjustedRisk = Math.min(150, adjustedRisk + 5);
            }
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Critical operation without authorization"))
                .type(VulnerabilityType.BFLA)
                .severity(finalSeverity)
                .riskScore(adjustedRisk)
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
                .evidence(withSchemaEvidence(
                    buildControlEvidence("Критичная операция без role-based auth",
                        riskScore, adjustedRisk, strongAccessControls, consentBankingContext),
                    privilegeSchemaNotes))
                .build());
        }
        
        // 4. DELETE/PUT без доп. авторизации
        if (CRITICAL_METHODS.contains(method) && !requiresAuth) {
            // Критичные методы без auth - используем SmartAnalyzer
            Severity severity = (baseSeverity == Severity.CRITICAL || riskScore > 100) ? 
                Severity.CRITICAL : Severity.HIGH;
            if (schemaStrongGuard) {
                severity = downgradeSeverity(severity);
            }
            Severity finalSeverity = applySeverityModifiers(severity, strongAccessControls, consentBankingContext, Severity.HIGH);
            int adjustedRisk = adjustRiskScoreForControls(riskScore, strongAccessControls, consentBankingContext);
            if (schemaStrongGuard) {
                adjustedRisk = Math.max(0, adjustedRisk - 8);
            } else if (schemaUnguarded) {
                adjustedRisk = Math.min(150, adjustedRisk + 5);
            }
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Dangerous HTTP method without authorization"))
                .type(VulnerabilityType.BFLA)
                .severity(finalSeverity)
                .riskScore(adjustedRisk)
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
                .evidence(withSchemaEvidence(
                    buildControlEvidence(method + " без security",
                        riskScore, adjustedRisk, strongAccessControls, consentBankingContext),
                    privilegeSchemaNotes))
                .build());
        }

        // 5. Телеком-критичные операции (SIM swap, роуминг) без авторизации
        if (isTelecomCritical && !requiresAuth) {
            int adjustedRisk = adjustRiskScoreForControls(riskScore, strongAccessControls, consentBankingContext);
            if (schemaStrongGuard) {
                adjustedRisk = Math.max(0, adjustedRisk - 8);
            } else if (schemaUnguarded) {
                adjustedRisk = Math.min(150, adjustedRisk + 5);
            }
            Severity finalSeverity = applySeverityModifiers(Severity.CRITICAL, strongAccessControls, consentBankingContext, Severity.HIGH);
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Telecom operation without authorization"))
                .type(VulnerabilityType.BFLA)
                .severity(finalSeverity)
                .riskScore(adjustedRisk)
                .title("Телеком операция без авторизации")
                .description(String.format(
                    "Эндпоинт %s %s выполняет критичную телеком операцию (SIM swap/roaming), но не требует авторизации",
                    method, path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Добавьте обязательную аутентификацию, 2FA и проверку роли оператора при выполнении телеком операций." )
                .owaspCategory("API5:2023 - Broken Function Level Authorization")
                .impactLevel("SIM_SWAP: Потеря контроля над номером")
                .evidence(withSchemaEvidence(
                    buildControlEvidence("Телеком критичная операция без security", riskScore, adjustedRisk,
                        strongAccessControls, consentBankingContext),
                    privilegeSchemaNotes))
                .build());
        }

        // 6. Телеком операции без проверки роли
        if (isTelecomOperation && requiresAuth && !hasRoleCheck) {
            Severity severity = applySeverityModifiers(Severity.HIGH, strongAccessControls, consentBankingContext, Severity.MEDIUM);
            if (schemaStrongGuard) {
                severity = downgradeSeverity(severity);
            }
            int adjustedRisk = adjustRiskScoreForControls(riskScore, strongAccessControls, consentBankingContext);
            if (schemaStrongGuard) {
                adjustedRisk = Math.max(0, adjustedRisk - 6);
            } else if (schemaUnguarded) {
                adjustedRisk = Math.min(150, adjustedRisk + 4);
            }
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Telecom operation without role check"))
                .type(VulnerabilityType.BFLA)
                .severity(severity)
                .riskScore(adjustedRisk)
                .title("Телеком операция без проверки роли")
                .description(String.format(
                    "Эндпоинт %s %s управляет телеком сервисами, но отсутствует проверка роли/прав доступа",
                    method, path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Настройте RBAC: только операторы/админы должны выполнять SIM swap, roaming activation и управление тарифами." )
                .owaspCategory("API5:2023 - Broken Function Level Authorization")
                .evidence(withSchemaEvidence(
                    buildControlEvidence("Нет role-based проверки для телеком операции", riskScore, adjustedRisk,
                        strongAccessControls, consentBankingContext),
                    privilegeSchemaNotes))
                .build());
        }

        // 7. Дистанционное управление автомобилем без авторизации/ролей
        if (isRemoteVehicleControl && !requiresAuth) {
            int adjustedRisk = adjustRiskScoreForControls(riskScore, strongAccessControls, consentBankingContext);
            if (schemaStrongGuard) {
                adjustedRisk = Math.max(0, adjustedRisk - 8);
            } else if (schemaUnguarded) {
                adjustedRisk = Math.min(150, adjustedRisk + 5);
            }
            Severity finalSeverity = applySeverityModifiers(Severity.CRITICAL, strongAccessControls, consentBankingContext, Severity.HIGH);
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Remote vehicle control without authorization"))
                .type(VulnerabilityType.BFLA)
                .severity(finalSeverity)
                .riskScore(adjustedRisk)
                .title("Удалённое управление автомобилем без авторизации")
                .description(String.format(
                    "Эндпоинт %s %s управляет функциями автомобиля (unlock/start), но не требует авторизации",
                    method, path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Требуйте авторизацию, 2FA и device binding для всех remote control операций." )
                .owaspCategory("API5:2023 - Broken Function Level Authorization")
                .impactLevel("VEHICLE_TAKEOVER: Угон или вмешательство")
                .evidence(withSchemaEvidence(
                    buildControlEvidence("Connected car remote control без security", riskScore, adjustedRisk,
                        strongAccessControls, consentBankingContext),
                    privilegeSchemaNotes))
                .build());
        }

        if (isRemoteVehicleControl && requiresAuth && !hasRoleCheck) {
            Severity severity = applySeverityModifiers(Severity.HIGH, strongAccessControls, consentBankingContext, Severity.MEDIUM);
            if (schemaStrongGuard) {
                severity = downgradeSeverity(severity);
            }
            int adjustedRisk = adjustRiskScoreForControls(riskScore, strongAccessControls, consentBankingContext);
            if (schemaStrongGuard) {
                adjustedRisk = Math.max(0, adjustedRisk - 6);
            } else if (schemaUnguarded) {
                adjustedRisk = Math.min(150, adjustedRisk + 4);
            }
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Remote vehicle control without role check"))
                .type(VulnerabilityType.BFLA)
                .severity(severity)
                .riskScore(adjustedRisk)
                .title("Нет проверки роли для remote vehicle control")
                .description(String.format(
                    "Операция %s %s позволяет управлять автомобилем, но не проверяет роль владельца",
                    method, path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Внедрите ограничения: только владелец/доверенные устройства могут выполнять команды; используйте RBAC/ACL." )
                .owaspCategory("API5:2023 - Broken Function Level Authorization")
                .impactLevel("SAFETY_RISK: Контроль над транспортом")
                .evidence(withSchemaEvidence(
                    buildControlEvidence("Remote control без role-based auth", riskScore, adjustedRisk,
                        strongAccessControls, consentBankingContext),
                    privilegeSchemaNotes))
                .build());
        }

        if (isConnectedCarOperation && !isRemoteVehicleControl && !requiresAuth) {
            Severity severity = applySeverityModifiers(Severity.HIGH, strongAccessControls, consentBankingContext, Severity.MEDIUM);
            if (schemaStrongGuard) {
                severity = downgradeSeverity(severity);
            }
            int adjustedRisk = adjustRiskScoreForControls(riskScore, strongAccessControls, consentBankingContext);
            if (schemaStrongGuard) {
                adjustedRisk = Math.max(0, adjustedRisk - 8);
            } else if (schemaUnguarded) {
                adjustedRisk = Math.min(150, adjustedRisk + 5);
            }
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Connected car operation without authorization"))
                .type(VulnerabilityType.BFLA)
                .severity(severity)
                .riskScore(adjustedRisk)
                .title("Connected car операция без авторизации")
                .description(String.format(
                    "Эндпоинт %s %s относится к connected car сервисам, но не требует авторизации",
                    method, path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Добавьте аутентификацию и контроль устройств для всех телематических операций." )
                .owaspCategory("API5:2023 - Broken Function Level Authorization")
                .impactLevel("CONNECTED_CAR: Несанкционированный доступ к телематике")
                .evidence(withSchemaEvidence(
                    buildControlEvidence("Connected car endpoint без security", riskScore, adjustedRisk,
                        strongAccessControls, consentBankingContext),
                    privilegeSchemaNotes))
                .build());
        }

        if (isConnectedCarOperation && !isRemoteVehicleControl && requiresAuth && !hasRoleCheck) {
            Severity severity = applySeverityModifiers(Severity.MEDIUM, strongAccessControls, consentBankingContext, Severity.LOW);
            int adjustedRisk = adjustRiskScoreForControls(riskScore, strongAccessControls, consentBankingContext);
            if (schemaStrongGuard) {
                adjustedRisk = Math.max(0, adjustedRisk - 6);
            } else if (schemaUnguarded) {
                adjustedRisk = Math.min(150, adjustedRisk + 4);
            }
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BFLA, path, method, null,
                    "Connected car operation without role check"))
                .type(VulnerabilityType.BFLA)
                .severity(severity)
                .riskScore(adjustedRisk)
                .title("Connected car операция без проверки роли")
                .description(String.format(
                    "Операция %s %s связана с телематикой, но отсутствует проверка роли/прав.",
                    method, path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Используйте RBAC и привязку устройств для телематических операций." )
                .owaspCategory("API5:2023 - Broken Function Level Authorization")
                .impactLevel("CONNECTED_CAR: Неавторизованные телематические операции")
                .evidence(withSchemaEvidence(
                    buildControlEvidence("Connected car endpoint без role-based auth", riskScore, adjustedRisk,
                        strongAccessControls, consentBankingContext),
                    privilegeSchemaNotes))
                .build());
        }

        return vulnerabilities;
    }

    private List<Parameter> combineParameters(List<Parameter> inheritedParameters, Operation operation) {
        List<Parameter> all = new ArrayList<>();
        if (inheritedParameters != null) {
            for (Parameter parameter : inheritedParameters) {
                if (parameter != null) {
                    all.add(parameter);
                }
            }
        }
        if (operation != null && operation.getParameters() != null) {
            for (Parameter parameter : operation.getParameters()) {
                if (parameter != null) {
                    all.add(parameter);
                }
            }
        }
        return all;
    }

    private List<PrivilegeField> collectPrivilegeFields(List<Parameter> parameters,
                                                        Operation operation,
                                                        SchemaConstraintAnalyzer constraintAnalyzer) {
        if (constraintAnalyzer == null) {
            return Collections.emptyList();
        }
        List<PrivilegeField> result = new ArrayList<>();
        Set<String> unique = new HashSet<>();

        if (parameters != null) {
            for (Parameter parameter : parameters) {
                if (parameter == null || parameter.getName() == null) {
                    continue;
                }
                String name = parameter.getName();
                String lower = name.toLowerCase(Locale.ROOT);
                if (!looksLikePrivilegeField(lower)) {
                    continue;
                }
                SchemaConstraints constraints = constraintAnalyzer.analyzeParameter(parameter);
                String key = (parameter.getIn() != null ? parameter.getIn().toLowerCase(Locale.ROOT) : "param")
                    + ":" + lower;
                if (unique.add(key)) {
                    result.add(new PrivilegeField(name,
                        parameter.getIn() != null ? parameter.getIn() : "param",
                        name,
                        constraints));
                }
            }
        }

        if (operation != null && operation.getRequestBody() != null &&
            operation.getRequestBody().getContent() != null) {
            operation.getRequestBody().getContent().forEach((mediaType, media) -> {
                if (media == null || media.getSchema() == null) {
                    return;
                }
                collectPrivilegeFieldsFromSchema(null, media.getSchema(), constraintAnalyzer,
                    new HashSet<>(), "$", result, unique);
            });
        }

        return result;
    }

    private void collectPrivilegeFieldsFromSchema(String propertyName,
                                                  Schema<?> schema,
                                                  SchemaConstraintAnalyzer constraintAnalyzer,
                                                  Set<Schema<?>> visited,
                                                  String pointer,
                                                  List<PrivilegeField> result,
                                                  Set<String> unique) {
        if (schema == null || constraintAnalyzer == null) {
            return;
        }
        if (!visited.add(schema)) {
            return;
        }
        SchemaConstraints constraints = constraintAnalyzer.analyzeSchema(schema);
        if (propertyName != null && looksLikePrivilegeField(propertyName.toLowerCase(Locale.ROOT))) {
            String key = "body:" + pointer.toLowerCase(Locale.ROOT);
            if (unique.add(key)) {
                result.add(new PrivilegeField(propertyName, "body", pointer, constraints));
            }
        }

        Map<String, Schema<?>> properties = castSchemaMap(schema.getProperties());
        if (properties != null) {
            for (Map.Entry<String, Schema<?>> entry : properties.entrySet()) {
                Schema<?> child = entry.getValue();
                if (child == null) {
                    continue;
                }
                String childPointer = pointer.endsWith(".") ? pointer + entry.getKey() : pointer + "." + entry.getKey();
                collectPrivilegeFieldsFromSchema(entry.getKey(), child, constraintAnalyzer,
                    new HashSet<>(visited), childPointer, result, unique);
            }
        }

        if (schema.getAllOf() != null) {
            for (Schema<?> sub : schema.getAllOf()) {
                collectPrivilegeFieldsFromSchema(propertyName, sub, constraintAnalyzer,
                    new HashSet<>(visited), pointer, result, unique);
            }
        }
        if (schema.getOneOf() != null) {
            int index = 0;
            for (Schema<?> sub : schema.getOneOf()) {
                collectPrivilegeFieldsFromSchema(propertyName, sub, constraintAnalyzer,
                    new HashSet<>(visited), pointer + ".oneOf[" + index + "]", result, unique);
                index++;
            }
        }
        if (schema.getAnyOf() != null) {
            int index = 0;
            for (Schema<?> sub : schema.getAnyOf()) {
                collectPrivilegeFieldsFromSchema(propertyName, sub, constraintAnalyzer,
                    new HashSet<>(visited), pointer + ".anyOf[" + index + "]", result, unique);
                index++;
            }
        }

        if (schema.getItems() != null) {
            collectPrivilegeFieldsFromSchema(propertyName,
                schema.getItems(), constraintAnalyzer, new HashSet<>(visited), pointer + "[]", result, unique);
        }
    }

    private boolean looksLikePrivilegeField(String lowerName) {
        return lowerName.contains("role") ||
            lowerName.contains("permission") ||
            lowerName.contains("scope") ||
            lowerName.contains("status") ||
            lowerName.contains("tier") ||
            lowerName.contains("level") ||
            lowerName.contains("group") ||
            lowerName.contains("profile") ||
            lowerName.contains("plan") ||
            lowerName.contains("access") ||
            lowerName.contains("action") ||
            lowerName.contains("operation") ||
            lowerName.contains("mode") ||
            lowerName.contains("privilege");
    }

    private List<String> buildPrivilegeEvidence(List<PrivilegeField> fields) {
        if (fields == null || fields.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> notes = new ArrayList<>();
        for (PrivilegeField field : fields) {
            String guardLabel = field.isGuarded() ? "guarded" : "unguarded";
            String pointer = field.pointer != null ? field.pointer : field.name;
            StringBuilder sb = new StringBuilder()
                .append(field.location)
                .append("(")
                .append(pointer)
                .append("): ")
                .append(guardLabel);
            String note = field.schemaNote();
            if (note != null) {
                sb.append(" - ").append(note);
            }
            notes.add(sb.toString());
        }
        return notes;
    }

    private String withSchemaEvidence(String baseEvidence, List<String> schemaNotes) {
        if (schemaNotes == null || schemaNotes.isEmpty()) {
            return baseEvidence;
        }
        return baseEvidence + ". " + String.join("; ", schemaNotes);
    }

    private static final class PrivilegeField {
        final String name;
        final String location;
        final String pointer;
        final SchemaConstraints constraints;

        PrivilegeField(String name, String location, String pointer, SchemaConstraints constraints) {
            this.name = name;
            this.location = location;
            this.pointer = pointer;
            this.constraints = constraints;
        }

        boolean isGuarded() {
            if (constraints == null) {
                return false;
            }
            if (!constraints.isUserControlled()) {
                return true;
            }
            return com.vtb.scanner.heuristics.EnhancedRules.isGuardLikelySafe(constraints);
        }

        String schemaNote() {
            return constraints != null ? constraints.buildEvidenceNote() : null;
        }
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
    
    private boolean hasRoleBasedAuth(Operation operation, String path, OpenAPI openAPI) {
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
        return AccessControlHeuristics.hasExplicitAccessControl(operation, path, openAPI);
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

    private String combineOperationText(Operation operation) {
        if (operation == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        if (operation.getSummary() != null) {
            sb.append(operation.getSummary().toLowerCase(Locale.ROOT)).append(' ');
        }
        if (operation.getDescription() != null) {
            sb.append(operation.getDescription().toLowerCase(Locale.ROOT)).append(' ');
        }
        return sb.toString();
    }

    private boolean isTelecomOperation(String path, String combinedText) {
        String target = (path != null ? path : "") + " " + combinedText;
        return TELECOM_KEYWORDS.stream().anyMatch(target::contains);
    }

    private boolean isTelecomCriticalOperation(String path, String combinedText) {
        String target = (path != null ? path : "") + " " + combinedText;
        return TELECOM_CRITICAL_KEYWORDS.stream().anyMatch(target::contains);
    }

    private boolean isConnectedCarOperation(String path, String combinedText) {
        String target = (path != null ? path : "") + " " + combinedText;
        return CONNECTED_CAR_KEYWORDS.stream().anyMatch(target::contains);
    }

    private boolean isRemoteVehicleControl(String path, String combinedText) {
        String target = (path != null ? path : "") + " " + combinedText;
        return CONNECTED_CAR_REMOTE_KEYWORDS.stream().anyMatch(target::contains);
    }

    private static final Set<String> TELECOM_KEYWORDS = Set.of(
        "msisdn", "sim", "e-sim", "esim", "imsi", "iccid", "tariff", "roaming", "subscriber",
        "перенос номера", "смена тарифа", "пополнение", "баланс", "услуга связи", "трафик"
    );
    private static final Set<String> TELECOM_CRITICAL_KEYWORDS = Set.of(
        "sim swap", "sim-swap", "sim change", "esim activation", "roaming activation", "transfer msisdn",
        "sim replacement", "msisdn transfer", "tariff upgrade",
        "запрос puk", "смена sim", "активация e-sim", "активация роуминга", "перевыпуск sim", "блокировка sim"
    );
    private static final Set<String> CONNECTED_CAR_KEYWORDS = Set.of(
        "telematics", "connected car", "vehicle", "vin", "remote start", "door unlock", "ota",
        "lada connect", "удаленный запуск", "телематика", "управление автомобилем", "climate control"
    );
    private static final Set<String> CONNECTED_CAR_REMOTE_KEYWORDS = Set.of(
        "remote start", "remote unlock", "remote lock", "remote engine", "remote climate",
        "удаленный запуск", "дистанционный запуск", "удаленное открытие", "удаленное закрытие",
        "remote horn", "remote lights", "remote alarm", "engine stop", "door unlock"
    );

    private Severity applySeverityModifiers(Severity current,
                                            boolean hasStrongAccess,
                                            boolean consentBankingContext,
                                            Severity floor) {
        Severity result = current;
        if (hasStrongAccess) {
            result = downgradeSeverity(result);
        }
        if (consentBankingContext) {
            result = downgradeSeverity(result);
        }
        if (result.compareTo(floor) < 0) {
            result = floor;
        }
        return result;
    }

    private Severity downgradeSeverity(Severity current) {
        return switch (current) {
            case CRITICAL -> Severity.HIGH;
            case HIGH -> Severity.MEDIUM;
            case MEDIUM -> Severity.LOW;
            default -> current;
        };
    }

    private int adjustRiskScoreForControls(int original,
                                           boolean hasStrongAccess,
                                           boolean consentBankingContext) {
        int adjusted = original;
        if (hasStrongAccess) {
            adjusted -= 12;
        }
        if (consentBankingContext) {
            adjusted -= 8;
        }
        return Math.max(0, adjusted);
    }

    private String buildControlEvidence(String baseText,
                                        int originalRisk,
                                        int adjustedRisk,
                                        boolean hasStrongAccess,
                                        boolean consentBankingContext) {
        StringBuilder builder = new StringBuilder(baseText)
            .append(". Risk Score: ").append(originalRisk);
        if (adjustedRisk != originalRisk) {
            builder.append(" → ").append(adjustedRisk);
        }
        if (hasStrongAccess) {
            builder.append(". Обнаружены признаки сильной авторизации/securitySchemes.");
        }
        if (consentBankingContext) {
            builder.append(" Open Banking/consent контекст учтен.");
        }
        return builder.toString();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Schema<?>> castSchemaMap(Map<String, Schema> properties) {
        if (properties == null) {
            return null;
        }
        return (Map<String, Schema<?>>) (Map<?, ?>) properties;
    }
}

