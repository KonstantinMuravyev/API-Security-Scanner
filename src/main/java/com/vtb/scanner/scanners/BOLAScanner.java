package com.vtb.scanner.scanners;

import com.vtb.scanner.analysis.SchemaConstraintAnalyzer;
import com.vtb.scanner.analysis.SchemaConstraintAnalyzer.SchemaConstraints;
import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.deep.CorrelationEngine;
import com.vtb.scanner.knowledge.CVEMapper;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.util.AccessControlHeuristics;
import com.vtb.scanner.semantic.OperationClassifier;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.media.Schema;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Сканер для обнаружения уязвимостей BOLA (Broken Object Level Authorization)
 * API1:2023 - OWASP API Security Top 10
 * 
 * BOLA/IDOR возникает когда API не проверяет, имеет ли пользователь права 
 * доступа к запрашиваемому объекту
 */
@Slf4j
public class BOLAScanner implements VulnerabilityScanner {
    
    private final String targetUrl;
    
    // Используем EnhancedRules вместо хардкода!
    
    public BOLAScanner(String targetUrl) {
        this.targetUrl = targetUrl;
    }
    
    @Override
    public List<Vulnerability> scan(OpenAPI openAPI, OpenAPIParser parser) {
        log.info("Запуск ГЛУБОКОГО BOLA Scanner для {}...", targetUrl != null ? targetUrl : "N/A");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        SchemaConstraintAnalyzer constraintAnalyzer = new SchemaConstraintAnalyzer(openAPI);

        // УРОВЕНЬ 1: Базовая проверка эндпоинтов
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            vulnerabilities.addAll(checkPathForBOLA(path, pathItem, parser, openAPI, constraintAnalyzer));
        }
        
        // УРОВЕНЬ 2: ГЛУБОКИЙ - Корреляционный анализ (BOLA цепочки)
        log.info("Запуск корреляционного анализа (BOLA chains)...");
        List<CorrelationEngine.BOLAChain> chains = CorrelationEngine.findBOLAChains(openAPI);
        
        for (CorrelationEngine.BOLAChain chain : chains) {
            // Получаем знания о BOLA
            CVEMapper.VulnerabilityKnowledge knowledge = CVEMapper.getKnowledge(VulnerabilityType.BOLA);
            
            Severity severity = chain.getSeverity().equals("CRITICAL") ? Severity.CRITICAL : Severity.HIGH;
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BOLA, chain.getResourceEndpoint(), "GET", null,
                    "BOLA exploitation chain detected"))
                .type(VulnerabilityType.BOLA)
                .severity(severity)
                .title("ОБНАРУЖЕНА BOLA цепочка эксплуатации!")
                .description(String.format(
                    "Найдена эксплуатируемая BOLA цепочка:\n\n" +
                    "Шаги атаки:\n%s\n\n" +
                    "Анализ:\n" +
                    "• List endpoint (%s): %s\n" +
                    "• Resource endpoint (%s): БЕЗ аутентификации!\n\n" +
                    "Злоумышленник может:\n" +
                    "1. Получить список всех ID\n" +
                    "2. Перебрать чужие ID\n" +
                    "3. Получить доступ к чужим данным\n\n" +
                    "Это ПОДТВЕРЖДЁННАЯ цепочка эксплуатации!",
                    String.join("\n", chain.getSteps()),
                    chain.getListEndpoint(),
                    chain.isListHasAuth() ? "с аутентификацией" : "БЕЗ аутентификации",
                    chain.getResourceEndpoint()
                ))
                .endpoint(chain.getResourceEndpoint())
                .method("GET")
                .recommendation(
                    "НЕМЕДЛЕННО исправьте:\n\n" +
                    "1. Добавьте аутентификацию для " + chain.getResourceEndpoint() + "\n" +
                    "2. ОБЯЗАТЕЛЬНО проверяйте владельца объекта:\n\n" +
                    "   // Плохо:\n" +
                    "   @GetMapping(\"/users/{id}\")\n" +
                    "   public User getUser(@PathVariable Long id) {\n" +
                    "       return userRepo.findById(id); // Нет проверки!\n" +
                    "   }\n\n" +
                    "   // Хорошо:\n" +
                    "   @GetMapping(\"/users/{id}\")\n" +
                    "   public User getUser(@PathVariable Long id, Principal principal) {\n" +
                    "       User current = getCurrentUser(principal);\n" +
                    "       User target = userRepo.findById(id);\n" +
                    "       \n" +
                    "       if (!current.getId().equals(id) && !current.isAdmin()) {\n" +
                    "           throw new AccessDeniedException();\n" +
                    "       }\n" +
                    "       return target;\n" +
                    "   }\n\n" +
                    "3. Скройте список ID от неавторизованных пользователей"
                )
                .owaspCategory("API1:2023 - BOLA (EXPLOITATION CHAIN DETECTED!)")
                .evidence("Корреляция: " + chain.getListEndpoint() + " → " + chain.getResourceEndpoint())
                .cwe(knowledge.getCwe())
                .cveExamples(knowledge.getCveExamples())
                .owaspRating(knowledge.getOwaspRating())
                .build());
        }
        
        log.info("BOLA Scanner завершен. Найдено уязвимостей: {}", vulnerabilities.size());
        log.info("  - Базовых BOLA: {}", vulnerabilities.size() - chains.size());
        log.info("  - BOLA цепочек: {}", chains.size());
        
        return vulnerabilities;
    }
    
    private boolean isCatalogResource(String path, Operation operation) {
        String lowerPath = path != null ? path.toLowerCase(Locale.ROOT) : "";
        if (lowerPath.contains("/products") || lowerPath.contains("catalog") || lowerPath.contains("tariff")) {
            return true;
        }
        if (operation == null) {
            return false;
        }
        StringBuilder text = new StringBuilder();
        if (operation.getSummary() != null) {
            text.append(operation.getSummary().toLowerCase(Locale.ROOT)).append(' ');
        }
        if (operation.getDescription() != null) {
            text.append(operation.getDescription().toLowerCase(Locale.ROOT));
        }
        String combined = text.toString();
        return combined.contains("catalog") || combined.contains("product list") || combined.contains("public offer");
    }
    
    /**
     * Проверка пути на BOLA уязвимости
     */
    private List<Vulnerability> checkPathForBOLA(String path,
                                                 PathItem pathItem,
                                                 OpenAPIParser parser,
                                                 OpenAPI openAPI,
                                                 SchemaConstraintAnalyzer constraintAnalyzer) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Проверяем GET
        if (pathItem.getGet() != null) {
            vulnerabilities.addAll(checkOperation(path, "GET", pathItem.getGet(), parser, openAPI,
                pathItem.getParameters(), constraintAnalyzer));
        }
        
        // Проверяем PUT/PATCH/DELETE - особо опасные для BOLA
        if (pathItem.getPut() != null) {
            vulnerabilities.addAll(checkOperation(path, "PUT", pathItem.getPut(), parser, openAPI,
                pathItem.getParameters(), constraintAnalyzer));
        }
        if (pathItem.getPatch() != null) {
            vulnerabilities.addAll(checkOperation(path, "PATCH", pathItem.getPatch(), parser, openAPI,
                pathItem.getParameters(), constraintAnalyzer));
        }
        if (pathItem.getDelete() != null) {
            vulnerabilities.addAll(checkOperation(path, "DELETE", pathItem.getDelete(), parser, openAPI,
                pathItem.getParameters(), constraintAnalyzer));
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка конкретной операции
     */
    private List<Vulnerability> checkOperation(String path,
                                               String method,
                                               Operation operation,
                                               OpenAPIParser parser,
                                               OpenAPI openAPI,
                                               List<Parameter> inheritedParameters,
                                               SchemaConstraintAnalyzer constraintAnalyzer) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (isCatalogResource(path, operation)) {
            return vulnerabilities;
        }
        
        // ИСПОЛЬЗУЕМ SmartAnalyzer!
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
            path, method, operation, openAPI);
        Severity smartSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
        
        List<Parameter> allParameters = combineParameters(inheritedParameters, operation);

        boolean hasExplicitAccessControl = AccessControlHeuristics.hasExplicitAccessControl(operation, path, openAPI);
        boolean hasConsentEvidence = AccessControlHeuristics.hasConsentEvidence(operation, openAPI);
        boolean hasStrongAuthorization = AccessControlHeuristics.hasStrongAuthorization(operation, openAPI);
        boolean isOpenBankingOperation = AccessControlHeuristics.isOpenBankingOperation(path, operation, openAPI);
        com.vtb.scanner.semantic.ContextAnalyzer.APIContext apiContext = com.vtb.scanner.semantic.ContextAnalyzer.detectContext(openAPI);
        List<IdentifierCandidate> pathIdentifiers = collectPathIdentifiers(path, allParameters, constraintAnalyzer);
        boolean hasIdInPath = !pathIdentifiers.isEmpty();
        OperationClassifier.OperationType opType =
            OperationClassifier.classify(path, method, operation);
        
        // Если эндпоинт содержит ID и не требует аутентификации - критичная BOLA
        if (hasIdInPath && !parser.requiresAuthentication(operation)) {
            // Severity: макс из SmartAnalyzer и CRITICAL (т.к. BOLA без auth!)
            Severity severity = Severity.CRITICAL;
            if (smartSeverity == Severity.CRITICAL || riskScore > 100) {
                severity = Severity.CRITICAL;
            } else if (smartSeverity == Severity.HIGH) {
                severity = Severity.HIGH;
            }

            if (shouldDowngradeDueToStrongAccess(hasStrongAuthorization, hasExplicitAccessControl,
                hasConsentEvidence, isOpenBankingOperation, apiContext)) {
                severity = downgradeSeverity(severity);
                riskScore = Math.max(0, riskScore - 12);
            }

            if (severity.compareTo(Severity.MEDIUM) <= 0) {
                return vulnerabilities;
            }
            
            List<String> schemaGuards = extractEvidenceNotes(pathIdentifiers);
            vulnerabilities.add(createBolaVulnerability(
                path, method, 
                severity,
                riskScore,
                "Эндпоинт с параметром ID не защищен аутентификацией",
                "Любой пользователь может получить доступ к объектам других пользователей, " +
                "просто изменяя ID в запросе",
                "Добавьте обязательную аутентификацию и проверку владельца объекта",
                schemaGuards
            ));
        }
        // Если есть ID но нет проверки авторизации
        else if (hasIdInPath && parser.requiresAuthentication(operation)) {
            if (shouldReportAuthenticatedBola(hasExplicitAccessControl, hasConsentEvidence, hasStrongAuthorization,
                isOpenBankingOperation, apiContext, operation, opType)) {
                vulnerabilities.add(createBolaVulnerability(
                    path, method,
                    determineAuthenticatedSeverity(smartSeverity, riskScore, hasStrongAuthorization, hasExplicitAccessControl,
                        hasConsentEvidence, isOpenBankingOperation, apiContext),
                    adjustAuthenticatedRiskScore(riskScore, hasStrongAuthorization, hasExplicitAccessControl,
                        hasConsentEvidence, isOpenBankingOperation, apiContext),
                    "Эндпоинт с параметром ID может не проверять владельца объекта",
                    "В спецификации не указана проверка прав доступа к объекту. " +
                    "Убедитесь, что API проверяет, принадлежит ли объект текущему пользователю",
                    "Добавьте проверку владельца объекта перед выполнением операции",
                    extractEvidenceNotes(pathIdentifiers)
                ));
            }
        }
        
        // Проверяем query параметры
        if (operation.getParameters() != null) {
            for (Parameter param : operation.getParameters()) {
                // ИСПОЛЬЗУЕМ EnhancedRules!
                if (param.getName() != null &&
                    "query".equalsIgnoreCase(param.getIn()) &&
                    com.vtb.scanner.heuristics.EnhancedRules.isIDParameter(param.getName())) {
                    SchemaConstraints paramConstraints = constraintAnalyzer.analyzeParameter(param);
                    if (isGuarded(paramConstraints)) {
                        continue;
                    }
                    if (!parser.requiresAuthentication(operation) && !shouldDowngradeDueToStrongAccess(
                        hasStrongAuthorization, hasExplicitAccessControl, hasConsentEvidence, isOpenBankingOperation, apiContext)) {
                        List<String> evidence = new ArrayList<>();
                        String note = buildSchemaNote(paramConstraints);
                        if (note != null) {
                            evidence.add("query." + param.getName() + ": " + note);
                        }
                        vulnerabilities.add(createBolaVulnerability(
                            path, method,
                            Severity.HIGH,
                            riskScore,
                            "Параметр '" + param.getName() + "' может быть использован для BOLA атаки",
                            "Query параметр содержит идентификатор, но эндпоинт не защищен аутентификацией",
                            "Добавьте аутентификацию и проверку прав доступа",
                            evidence
                        ));
                    }
                }
            }
        }

        // Если ID в теле запроса (Mass Assignment-like сценарий)
        if (!hasExplicitAccessControl && !hasConsentEvidence && !hasStrongAuthorization &&
            operation.getRequestBody() != null &&
            operation.getRequestBody().getContent() != null &&
            AccessControlHeuristics.mentionsPersonalData(operation)) {
            List<IdentifierCandidate> bodyIdentifiers = collectBodyIdentifiers(operation, constraintAnalyzer);
            if (!bodyIdentifiers.isEmpty()) {
                vulnerabilities.add(createBolaVulnerability(
                    path, method,
                    Severity.MEDIUM,
                    riskScore,
                    "Чувствительные идентификаторы в теле запроса без признаков владения",
                    "Request body содержит персональные идентификаторы, но в спецификации нет явных признаков контроля собственника.",
                    "Проверьте, что сервер валидирует владельца объекта при обработке запроса",
                    extractEvidenceNotes(bodyIdentifiers)
                ));
            }
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

    private List<IdentifierCandidate> collectPathIdentifiers(String path,
                                                             List<Parameter> parameters,
                                                             SchemaConstraintAnalyzer constraintAnalyzer) {
        if (path == null) {
            return Collections.emptyList();
        }
        List<IdentifierCandidate> result = new ArrayList<>();
        String[] segments = path.split("/");
        Set<String> seen = new HashSet<>();
        for (String segment : segments) {
            if (!segment.contains("{") || !segment.contains("}")) {
                continue;
            }
            String rawName = segment.replace("{", "").replace("}", "");
            String normalized = rawName.toLowerCase(Locale.ROOT);
            if (!isLikelyIdentifier(normalized)) {
                continue;
            }
            SchemaConstraints constraints = resolveParameterConstraints(rawName, "path", parameters, constraintAnalyzer);
            if (isGuarded(constraints)) {
                continue;
            }
            if (seen.add(normalized)) {
                result.add(new IdentifierCandidate(rawName, "path", "{"+rawName+"}", constraints));
            }
        }
        if (parameters != null) {
            for (Parameter parameter : parameters) {
                if (parameter == null || parameter.getName() == null) {
                    continue;
                }
                if (!"path".equalsIgnoreCase(parameter.getIn())) {
                    continue;
                }
                String name = parameter.getName();
                String normalized = name.toLowerCase(Locale.ROOT);
                if (!isLikelyIdentifier(normalized)) {
                    continue;
                }
                SchemaConstraints constraints = constraintAnalyzer.analyzeParameter(parameter);
                if (isGuarded(constraints)) {
                    continue;
                }
                if (seen.add(normalized)) {
                    result.add(new IdentifierCandidate(name, "path", "{"+name+"}", constraints));
                }
            }
        }
        return result;
    }

    private SchemaConstraints resolveParameterConstraints(String name,
                                                          String location,
                                                          List<Parameter> parameters,
                                                          SchemaConstraintAnalyzer constraintAnalyzer) {
        if (name == null || constraintAnalyzer == null || parameters == null) {
            return null;
        }
        for (Parameter parameter : parameters) {
            if (parameter == null || parameter.getName() == null) {
                continue;
            }
            boolean nameMatch = parameter.getName().equalsIgnoreCase(name);
            boolean locationMatch = location == null || parameter.getIn() == null
                ? true
                : parameter.getIn().equalsIgnoreCase(location);
            if (nameMatch && locationMatch) {
                return constraintAnalyzer.analyzeParameter(parameter);
            }
        }
        return null;
    }

    private List<IdentifierCandidate> collectBodyIdentifiers(Operation operation,
                                                             SchemaConstraintAnalyzer constraintAnalyzer) {
        if (operation == null ||
            operation.getRequestBody() == null ||
            operation.getRequestBody().getContent() == null) {
            return Collections.emptyList();
        }
        List<IdentifierCandidate> result = new ArrayList<>();
        Set<String> unique = new HashSet<>();
        operation.getRequestBody().getContent().forEach((mediaTypeKey, mediaType) -> {
            if (mediaType == null || mediaType.getSchema() == null) {
                return;
            }
            collectBodyIdentifiersFromSchema(null, mediaType.getSchema(), constraintAnalyzer,
                new HashSet<>(), "$", result, unique);
        });
        return result;
    }

    private void collectBodyIdentifiersFromSchema(String propertyName,
                                                  Schema<?> schema,
                                                  SchemaConstraintAnalyzer constraintAnalyzer,
                                                  Set<Schema<?>> visited,
                                                  String pointer,
                                                  List<IdentifierCandidate> result,
                                                  Set<String> unique) {
        if (schema == null || constraintAnalyzer == null) {
            return;
        }
        if (!visited.add(schema)) {
            return;
        }
        SchemaConstraints constraints = constraintAnalyzer.analyzeSchema(schema);
        if (propertyName != null && isLikelyIdentifier(propertyName)) {
            if (!isGuarded(constraints)) {
                String key = "body:" + pointer.toLowerCase(Locale.ROOT);
                if (unique.add(key)) {
                    result.add(new IdentifierCandidate(propertyName, "body", pointer, constraints));
                }
            }
        }

        Map<String, Schema<?>> properties = castSchemaMap(schema.getProperties());
        if (properties != null) {
            for (Map.Entry<String, Schema<?>> entry : properties.entrySet()) {
                Schema<?> childSchema = entry.getValue();
                if (childSchema == null) {
                    continue;
                }
                String childPointer = pointer.endsWith(".") ? pointer + entry.getKey() : pointer + "." + entry.getKey();
                collectBodyIdentifiersFromSchema(entry.getKey(), childSchema, constraintAnalyzer,
                    new HashSet<>(visited), childPointer, result, unique);
            }
        }

        if (schema.getAllOf() != null) {
            for (Schema<?> subSchema : schema.getAllOf()) {
                collectBodyIdentifiersFromSchema(propertyName, subSchema, constraintAnalyzer,
                    new HashSet<>(visited), pointer, result, unique);
            }
        }
        if (schema.getOneOf() != null) {
            int index = 0;
            for (Schema<?> subSchema : schema.getOneOf()) {
                collectBodyIdentifiersFromSchema(propertyName, subSchema, constraintAnalyzer,
                    new HashSet<>(visited), pointer + ".oneOf[" + index + "]", result, unique);
                index++;
            }
        }
        if (schema.getAnyOf() != null) {
            int index = 0;
            for (Schema<?> subSchema : schema.getAnyOf()) {
                collectBodyIdentifiersFromSchema(propertyName, subSchema, constraintAnalyzer,
                    new HashSet<>(visited), pointer + ".anyOf[" + index + "]", result, unique);
                index++;
            }
        }

        if (schema.getItems() != null) {
            collectBodyIdentifiersFromSchema(propertyName,
                schema.getItems(), constraintAnalyzer, new HashSet<>(visited), pointer + "[]", result, unique);
        }
    }

    private boolean isGuarded(SchemaConstraints constraints) {
        if (constraints == null) {
            return false;
        }
        if (!constraints.isUserControlled()) {
            return true;
        }
        return com.vtb.scanner.heuristics.EnhancedRules.isGuardLikelySafe(constraints);
    }

    private String buildSchemaNote(SchemaConstraints constraints) {
        if (constraints == null) {
            return null;
        }
        return constraints.buildEvidenceNote();
    }

    private List<String> extractEvidenceNotes(List<IdentifierCandidate> candidates) {
        if (candidates == null || candidates.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> evidence = new ArrayList<>();
        for (IdentifierCandidate candidate : candidates) {
            String note = buildSchemaNote(candidate.constraints);
            if (note != null) {
                evidence.add(candidate.location + "(" + candidate.pointer + "): " + note);
            } else if (candidate.pointer != null) {
                evidence.add(candidate.location + "(" + candidate.pointer + ")");
            } else {
                evidence.add(candidate.location);
            }
        }
        return evidence;
    }

    private static final class IdentifierCandidate {
        final String name;
        final String location;
        final String pointer;
        final SchemaConstraints constraints;

        IdentifierCandidate(String name, String location, String pointer, SchemaConstraints constraints) {
            this.name = name;
            this.location = location;
            this.pointer = pointer;
            this.constraints = constraints;
        }
    }
    
    private boolean mentionsOwnership(Operation operation, OperationClassifier.OperationType opType) {
        if (operation == null) {
            return false;
        }
        String text = ((operation.getSummary() != null ? operation.getSummary() : "") +
            (operation.getDescription() != null ? operation.getDescription() : "")).toLowerCase();
        return text.contains("owner") ||
               text.contains("ownership") ||
               text.contains("владел") ||
               text.contains("принадлеж") ||
               text.contains("authorization") ||
               opType == OperationClassifier.OperationType.ADMIN_ACTION ||
               opType == OperationClassifier.OperationType.USER_MANAGEMENT ||
               opType == OperationClassifier.OperationType.ROLE_MANAGEMENT;
    }

    private boolean shouldReportAuthenticatedBola(boolean hasExplicitAccess, boolean hasConsent,
                                                  boolean hasStrongAuth, boolean isOpenBanking,
                                                  com.vtb.scanner.semantic.ContextAnalyzer.APIContext apiContext,
                                                  Operation operation,
                                                  OperationClassifier.OperationType opType) {
        if (hasExplicitAccess || hasStrongAuth || hasConsent) {
            return false;
        }
        if (isOpenBanking && apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.BANKING) {
            return false;
        }
        return !mentionsOwnership(operation, opType);
    }

    private boolean shouldDowngradeDueToStrongAccess(boolean hasStrongAuth, boolean hasExplicitAccess,
                                                     boolean hasConsent, boolean isOpenBanking,
                                                     com.vtb.scanner.semantic.ContextAnalyzer.APIContext apiContext) {
        if (hasStrongAuth || hasExplicitAccess) {
            return true;
        }
        return (hasConsent || isOpenBanking) && apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.BANKING;
    }

    private Severity determineAuthenticatedSeverity(Severity smartSeverity,
                                                    int riskScore,
                                                    boolean hasStrongAuth,
                                                    boolean hasExplicitAccess,
                                                    boolean hasConsent,
                                                    boolean isOpenBanking,
                                                    com.vtb.scanner.semantic.ContextAnalyzer.APIContext apiContext) {
        Severity severity = smartSeverity.compareTo(Severity.HIGH) < 0 ? Severity.HIGH : smartSeverity;
        if (hasStrongAuth || hasExplicitAccess) {
            severity = downgradeSeverity(severity);
        }
        if ((hasConsent || isOpenBanking) && apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.BANKING) {
            severity = downgradeSeverity(severity);
        }
        if (severity.compareTo(Severity.MEDIUM) < 0) {
            severity = Severity.MEDIUM;
        }
        return severity;
    }

    private int adjustAuthenticatedRiskScore(int riskScore,
                                             boolean hasStrongAuth,
                                             boolean hasExplicitAccess,
                                             boolean hasConsent,
                                             boolean isOpenBanking,
                                             com.vtb.scanner.semantic.ContextAnalyzer.APIContext apiContext) {
        int adjusted = riskScore;
        if (hasStrongAuth || hasExplicitAccess) {
            adjusted -= 12;
        }
        if ((hasConsent || isOpenBanking) && apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.BANKING) {
            adjusted -= 8;
        }
        return Math.max(0, adjusted);
    }

    private Severity downgradeSeverity(Severity current) {
        return switch (current) {
            case CRITICAL -> Severity.HIGH;
            case HIGH -> Severity.MEDIUM;
            case MEDIUM -> Severity.LOW;
            default -> current;
        };
    }

    private boolean isLikelyIdentifier(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.matches(".*(status|state|type|code|lang|locale|currency|country).*")) {
            return false;
        }
        if (lower.matches(".*(page|offset|limit|size).*")) {
            return false;
        }
        if (lower.contains("id") || lower.contains("uuid") || lower.contains("identifier")) {
            return true;
        }
        return lower.matches(".*(account|user|profile|transaction).*");
    }
    
    /**
     * Создать объект уязвимости BOLA
     * 
     * С ПОЛНЫМ НАБОРОМ: CVE/CWE + Confidence + Priority + Impact + RiskScore!
     */
    private Vulnerability createBolaVulnerability(String endpoint, String method, Severity severity,
                                                  int riskScore,
                                                  String title, String description, String recommendation,
                                                  List<String> evidenceDetails) {
        // Получаем профессиональную информацию
        CVEMapper.VulnerabilityKnowledge knowledge = CVEMapper.getKnowledge(VulnerabilityType.BOLA);
        
        // ИСПОЛЬЗУЕМ ConfidenceCalculator для ДИНАМИЧЕСКОГО расчета!
        Vulnerability tempVuln = Vulnerability.builder()
            .type(VulnerabilityType.BOLA)
            .severity(severity)
            .riskScore(riskScore)
            .gostRelated(false)
            .build();
        
        // РЕАЛЬНЫЙ расчет confidence на основе факторов!
        int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
            tempVuln, 
            null, // operation
            false, // hasCorrelation (базовая BOLA)
            riskScore > 0  // hasEvidence (есть risk score!)
        );
        
        // PRIORITY: на основе severity + confidence
        int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
            tempVuln, confidence
        );
        
        // IMPACT
        String impact = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateImpact(tempVuln);

        String evidence = "Обнаружен эндпоинт с идентификатором объекта без должной защиты. Risk Score: " + riskScore;
        if (evidenceDetails != null && !evidenceDetails.isEmpty()) {
            evidence += ". " + String.join("; ", evidenceDetails);
        }
        
        return Vulnerability.builder()
            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                VulnerabilityType.BOLA, endpoint, method, null, title))
            .type(VulnerabilityType.BOLA)
            .severity(severity)
            .title(title)
            .description(description)
            .endpoint(endpoint)
            .method(method)
            .recommendation(recommendation)
            .owaspCategory("API1:2023 - Broken Object Level Authorization")
            .evidence(evidence)
            // Профессиональная информация
            .cwe(knowledge.getCwe())
            .cveExamples(knowledge.getCveExamples())
            .owaspRating(knowledge.getOwaspRating())
            // Scoring
            .riskScore(riskScore)
            .confidence(confidence)
            .priority(priority)
            .impactLevel(impact)
            .build();
    }

    private Vulnerability createBolaVulnerability(String endpoint, String method, Severity severity,
                                                   int riskScore,
                                                   String title, String description, String recommendation) {
        return createBolaVulnerability(endpoint, method, severity, riskScore, title, description, recommendation, Collections.emptyList());
    }

    @SuppressWarnings("unchecked")
    private Map<String, Schema<?>> castSchemaMap(Map<String, Schema> properties) {
        if (properties == null) {
            return null;
        }
        return (Map<String, Schema<?>>) (Map<?, ?>) properties;
    }
}

