package com.vtb.scanner.analysis;

import com.vtb.scanner.deep.CorrelationEngine;
import com.vtb.scanner.deep.CorrelationEngine.DataSensitivity;
import com.vtb.scanner.heuristics.SmartAnalyzer;
import com.vtb.scanner.semantic.ContextAnalyzer;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.util.AccessControlHeuristics;
import com.vtb.scanner.heuristics.EnhancedRules;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.stream.Collectors;

/**
 * ИННОВАЦИЯ: Attack Surface Mapper
 * 
 * Строит карту поверхности атаки API:
 * - Граф зависимостей между эндпоинтами
 * - Цепочки эксплуатации уязвимостей
 * - Критичные точки входа
 * - Data flow анализ
 */
@Slf4j
public class AttackSurfaceMapper {
    
    /**
     * Построить карту поверхности атаки
     */
    public static AttackSurface map(OpenAPI openAPI) {
        log.info("Построение карты поверхности атаки...");
        
        AttackSurface surface = new AttackSurface();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) {
            return surface;
        }

        ContextAnalyzer.APIContext context = ContextAnalyzer.detectContext(openAPI);
        surface.setContext(context != null ? context.name() : ContextAnalyzer.APIContext.GENERAL.name());
        
        Map<String, EndpointNode> nodes = new HashMap<>();
        SchemaConstraintAnalyzer analyzer = new SchemaConstraintAnalyzer(openAPI);
        
        // 1. Создаем узлы для каждого эндпоинта
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // Для каждого метода
            if (pathItem.getGet() != null) {
                String key = "GET " + path;
                nodes.put(key, analyzeEndpoint(openAPI, path, "GET", pathItem.getGet(), analyzer));
            }
            if (pathItem.getPost() != null) {
                String key = "POST " + path;
                nodes.put(key, analyzeEndpoint(openAPI, path, "POST", pathItem.getPost(), analyzer));
            }
            if (pathItem.getPut() != null) {
                String key = "PUT " + path;
                nodes.put(key, analyzeEndpoint(openAPI, path, "PUT", pathItem.getPut(), analyzer));
            }
            if (pathItem.getDelete() != null) {
                String key = "DELETE " + path;
                nodes.put(key, analyzeEndpoint(openAPI, path, "DELETE", pathItem.getDelete(), analyzer));
            }
        }
        
        surface.setNodes(nodes);
        
        // 2. Находим связи между эндпоинтами
        surface.setRelationships(findRelationships(nodes));
        
        // 3. Определяем критичные точки входа
        List<EntryPoint> entryPointDetails = findEntryPoints(nodes);
        surface.setEntryPointDetails(entryPointDetails);
        surface.setEntryPoints(entryPointDetails.stream()
            .map(EntryPoint::getKey)
            .collect(Collectors.toList()));
        
        // 4. Находим цепочки атак
        surface.setAttackChains(findAttackChains(nodes, openAPI, context));
        addBolaChains(surface, openAPI, context);
        
        log.info("Attack Surface: {} эндпоинтов, {} связей, {} точек входа, {} цепочек атак",
            nodes.size(), surface.getRelationships().size(), 
            surface.getEntryPoints().size(), surface.getAttackChains().size());
        
        return surface;
    }
    
    private static EndpointNode analyzeEndpoint(OpenAPI openAPI,
                                                String path,
                                                String method,
                                                Operation operation,
                                                SchemaConstraintAnalyzer analyzer) {
        EndpointNode node = new EndpointNode();
        
        // КРИТИЧНО: Защита от NPE
        node.setPath(path != null ? path : "");
        node.setMethod(method != null ? method : "");
        
        boolean hasParameters = operation != null && operation.getParameters() != null && !operation.getParameters().isEmpty();
        node.setHasParameters(hasParameters);
        analyzeParameters(operation, analyzer, node);

        boolean securityScopes = operation != null && AccessControlHeuristics.hasSecurityScopes(operation, openAPI);
        boolean explicitAccess = operation != null && AccessControlHeuristics.hasExplicitAccessControl(operation, path, openAPI);
        boolean strongAuthorization = operation != null && AccessControlHeuristics.hasStrongAuthorization(operation, openAPI);
        boolean consentEvidence = operation != null && AccessControlHeuristics.hasConsentEvidence(operation, openAPI);
        boolean openBanking = operation != null && AccessControlHeuristics.isOpenBankingOperation(path, operation, openAPI);

        boolean requiresAuth = securityScopes || explicitAccess || strongAuthorization;
        node.setRequiresAuth(requiresAuth);
        node.setStrongAuth(strongAuthorization);
        node.setConsentRequired(consentEvidence);
        node.setOpenBanking(openBanking);

        if (consentEvidence) {
            node.getSignals().add("CONSENT_FLOW");
        }
        if (strongAuthorization) {
            node.getSignals().add("STRONG_AUTH");
        }
        if (openBanking) {
            node.getSignals().add("OPEN_BANKING");
        }
        
        // Определяем тип эндпоинта
        String safePath = path != null ? path : "";
        String safeMethod = method != null ? method : "";
        
        if (safePath.contains("{")) {
            node.setType("RESOURCE"); // Конкретный ресурс
        } else if ("GET".equals(safeMethod)) {
            node.setType("LIST"); // Список ресурсов
        } else if ("POST".equals(safeMethod)) {
            node.setType("CREATE"); // Создание
        } else {
            node.setType("ACTION"); // Действие
        }
        
        int riskScore = operation != null ? SmartAnalyzer.calculateRiskScore(safePath, safeMethod, operation, openAPI) : 0;
        node.setRiskScore(riskScore);
        Severity severity = operation != null ? SmartAnalyzer.severityFromRiskScore(riskScore) : null;
        node.setSeverity(severity != null ? severity.name() : "UNKNOWN");
        if (severity != null) {
            node.getSignals().add("SEVERITY_" + severity.name());
        }
        if (riskScore >= 150) {
            node.getSignals().add("HIGH_RISK");
        } else if (riskScore >= 100) {
            node.getSignals().add("ELEVATED_RISK");
        }

        if (!requiresAuth) {
            node.getSignals().add("NO_AUTH");
        } else if (!strongAuthorization && consentEvidence) {
            node.getSignals().add("CONSENT_ONLY");
        }

        DataSensitivity sensitivity = operation != null ? CorrelationEngine.analyzeResponseSensitivity(operation) : null;
        if (sensitivity != null) {
            node.setDataSensitivityLevel(sensitivity.getLevel());
            node.getSensitiveFields().addAll(sensitivity.getFields());
            if ("CRITICAL".equalsIgnoreCase(sensitivity.getLevel())) {
                node.getSignals().add("PII_CRITICAL");
            } else if ("HIGH".equalsIgnoreCase(sensitivity.getLevel())) {
                node.getSignals().add("PII_HIGH");
            }
        }

        boolean adminPath = safePath.toLowerCase(Locale.ROOT).contains("admin");
        boolean dangerousMethod = "DELETE".equalsIgnoreCase(safeMethod) || "PUT".equalsIgnoreCase(safeMethod) || "PATCH".equalsIgnoreCase(safeMethod);
        boolean highSeverity = severity == Severity.CRITICAL || severity == Severity.HIGH;
        boolean sensitiveData = sensitivity != null && ("CRITICAL".equalsIgnoreCase(sensitivity.getLevel()) || "HIGH".equalsIgnoreCase(sensitivity.getLevel()));
        boolean weaklyProtected = !requiresAuth || (!strongAuthorization && !consentEvidence);

        node.setCritical(
            weaklyProtected && (highSeverity || sensitiveData || adminPath) ||
                (dangerousMethod && !strongAuthorization) ||
                adminPath
        );
        
        return node;
    }

    private static void analyzeParameters(Operation operation,
                                          SchemaConstraintAnalyzer analyzer,
                                          EndpointNode node) {
        if (operation == null || operation.getParameters() == null) {
            return;
        }
        for (io.swagger.v3.oas.models.parameters.Parameter parameter : operation.getParameters()) {
            if (parameter == null || parameter.getName() == null) {
                continue;
            }
            SchemaConstraintAnalyzer.SchemaConstraints constraints =
                analyzer != null ? analyzer.analyzeParameter(parameter) : null;
            String name = parameter.getName();
            if (EnhancedRules.isSSRFRisk(parameter, constraints)) {
                addUnique(node.getSsrfParameters(), name);
                node.getSignals().add("SSRF_PARAM");
            }
            if (EnhancedRules.isSQLInjectionRisk(parameter, constraints)
                || EnhancedRules.isCommandInjectionRisk(parameter, constraints)) {
                addUnique(node.getInjectionParameters(), name);
                node.getSignals().add("INJECTION_PARAM");
            }
            if (looksLikePrivilegeField(name)) {
                addUnique(node.getPrivilegeParameters(), name);
                node.getSignals().add("PRIVILEGE_PARAM");
            }
        }
    }
    
    private static List<Relationship> findRelationships(Map<String, EndpointNode> nodes) {
        List<Relationship> relationships = new ArrayList<>();
        
        // Находим связи типа LIST → RESOURCE
        for (Map.Entry<String, EndpointNode> entry1 : nodes.entrySet()) {
            EndpointNode node1 = entry1.getValue();
            
            if (node1.getType().equals("LIST")) {
                // Ищем соответствующий RESOURCE эндпоинт
                String basePath = node1.getPath();
                
                for (Map.Entry<String, EndpointNode> entry2 : nodes.entrySet()) {
                    EndpointNode node2 = entry2.getValue();
                    
                    if (node2.getType().equals("RESOURCE") && 
                        node2.getPath().startsWith(basePath + "/")) {
                        
                        Relationship rel = new Relationship();
                        rel.setFrom(entry1.getKey());
                        rel.setTo(entry2.getKey());
                        rel.setType("LIST_TO_RESOURCE");
                        relationships.add(rel);
                    }
                }
            }
        }
        
        return relationships;
    }
    
    private static List<EntryPoint> findEntryPoints(Map<String, EndpointNode> nodes) {
        List<EntryPoint> entryPoints = new ArrayList<>();
        
        for (Map.Entry<String, EndpointNode> entry : nodes.entrySet()) {
            EndpointNode node = entry.getValue();
            
            // Точки входа - эндпоинты без auth
            boolean weakProtection = !node.isRequiresAuth() || (!node.isStrongAuth() && !node.isConsentRequired());
            boolean highRisk = node.getRiskScore() >= 120 ||
                "CRITICAL".equalsIgnoreCase(node.getSeverity()) ||
                "HIGH".equalsIgnoreCase(node.getSeverity());
            boolean signalNoAuth = node.getSignals().contains("NO_AUTH");
            boolean elevatedRisk = node.getRiskScore() >= 90;
            if (weakProtection && (highRisk || elevatedRisk || signalNoAuth)) {
                EntryPoint point = new EntryPoint();
                point.setKey(entry.getKey());
                point.setMethod(node.getMethod());
                point.setPath(node.getPath());
                point.setRequiresAuth(node.isRequiresAuth());
                point.setStrongAuth(node.isStrongAuth());
                point.setConsentRequired(node.isConsentRequired());
                point.setOpenBanking(node.isOpenBanking());
                point.setRiskScore(node.getRiskScore());
                point.setSeverity(node.getSeverity());
                point.setDataSensitivityLevel(node.getDataSensitivityLevel());
                point.setWeakProtection(weakProtection);
                point.setHighRisk(highRisk);
                point.setSignals(new ArrayList<>(new LinkedHashSet<>(node.getSignals())));
                point.setSensitiveFields(new ArrayList<>(node.getSensitiveFields()));
                point.setSsrfParameters(new ArrayList<>(node.getSsrfParameters()));
                point.setInjectionParameters(new ArrayList<>(node.getInjectionParameters()));
                point.setPrivilegeParameters(new ArrayList<>(node.getPrivilegeParameters()));
                entryPoints.add(point);
            }
        }
        
        entryPoints.sort(Comparator.comparingInt(EntryPoint::getRiskScore).reversed());
        return entryPoints;
    }
    
    private static List<AttackChain> findAttackChains(Map<String, EndpointNode> nodes, OpenAPI openAPI,
                                                      ContextAnalyzer.APIContext context) {
        List<AttackChain> chains = new ArrayList<>();
        
        // Ищем потенциальные цепочки атак
        // Например: /login (без rate limit) → получить токен → /admin (BOLA)
        
        for (Map.Entry<String, EndpointNode> entry : nodes.entrySet()) {
            EndpointNode node = entry.getValue();
            
            // Если это критичный эндпоинт без auth
            boolean weakProtection = !node.isRequiresAuth() || (!node.isStrongAuth() && !node.isConsentRequired());
            boolean highRisk = node.getRiskScore() >= 140 ||
                "CRITICAL".equalsIgnoreCase(node.getSeverity()) ||
                (node.getDataSensitivityLevel() != null && "CRITICAL".equalsIgnoreCase(node.getDataSensitivityLevel()));

            if (node.isCritical() && weakProtection && highRisk) {
                AttackChain chain = new AttackChain();
                chain.setSteps(buildEntryPointSteps(node));
                chain.setSeverity(adjustSeverity(
                    node.getSeverity() != null ? node.getSeverity() : "CRITICAL",
                    context,
                    true,
                    node.getDataSensitivityLevel()));
                chain.setTarget(entry.getKey());
                chain.setType("ENTRY_POINT");
                chain.setExploitable(true);
                chain.setRiskScore(node.getRiskScore());
                chain.getSignals().addAll(node.getSignals());
                if (node.getDataSensitivityLevel() != null) {
                    chain.setDataSensitivityLevel(node.getDataSensitivityLevel());
                    chain.getSensitiveFields().addAll(node.getSensitiveFields());
                }
                chain.getMetadata().put("method", node.getMethod());
                chain.getMetadata().put("path", node.getPath());
                chain.getMetadata().put("weakProtection", String.valueOf(weakProtection));
                chain.getMetadata().put("signals", String.join(", ", node.getSignals()));
                chains.add(chain);
            }
            
            // Цепочка: List endpoint → BOLA в Resource
            if ("RESOURCE".equals(node.getType()) && weakProtection) {
                // КРИТИЧНО: Защита от NPE при substring
                String nodePath = node.getPath();
                if (nodePath != null && nodePath.contains("/")) {
                    String basePath = nodePath.substring(0, nodePath.lastIndexOf("/"));
                    
                    if (basePath != null && openAPI.getPaths() != null && 
                        openAPI.getPaths().containsKey(basePath)) {
                        String listKey = "GET " + basePath;
                        EndpointNode listNode = nodes.get(listKey);

                        AttackChain chain = new AttackChain();
                        chain.setSteps(Arrays.asList(
                            "1. GET " + basePath + " — получить список идентификаторов",
                            "2. Выбрать чужой идентификатор",
                            "3. " + node.getMethod() + " " + node.getPath() + " — доступ к чужим данным (BOLA)"
                        ));
                        String dataSensitivity = node.getDataSensitivityLevel();
                        chain.setSeverity(adjustSeverity(
                            node.getSeverity() != null ? node.getSeverity() : "HIGH",
                            context,
                            true,
                            dataSensitivity));
                        chain.setTarget(entry.getKey());
                        chain.setType("LIST_TO_RESOURCE");
                        chain.setExploitable(true);
                        chain.setRiskScore(Math.max(node.getRiskScore(), listNode != null ? listNode.getRiskScore() : 0));
                        chain.setDataSensitivityLevel(dataSensitivity);
                        if (dataSensitivity != null) {
                            chain.getSensitiveFields().addAll(node.getSensitiveFields());
                        }
                        chain.getMetadata().put("listEndpoint", basePath);
                        chain.getMetadata().put("listProtected", String.valueOf(listNode != null && listNode.isRequiresAuth()));
                        chain.getMetadata().put("resourceSignals", String.join(", ", node.getSignals()));
                        if (listNode != null) {
                            chain.getSignals().addAll(listNode.getSignals());
                        }
                        chain.getSignals().addAll(node.getSignals());
                        chains.add(chain);
                    }
                }
            }
        }
        
        return chains;
    }
    
    private static List<String> buildEntryPointSteps(EndpointNode node) {
        List<String> steps = new ArrayList<>();
        steps.add("1. Прямой доступ к " + node.getMethod() + " " + node.getPath());
        if (!node.isRequiresAuth()) {
            steps.add("2. Нет описанной аутентификации/авторизации");
        } else if (!node.isStrongAuth() && node.isConsentRequired()) {
            steps.add("2. Доступ ограничен только consent-параметрами (без сильной авторизации)");
        } else {
            steps.add("2. Слабая защита (недостаточные механизмы)");
        }
        if (node.getDataSensitivityLevel() != null &&
            !"LOW".equalsIgnoreCase(node.getDataSensitivityLevel())) {
            steps.add("3. Получение чувствительных данных (" + node.getDataSensitivityLevel() + ")");
        } else if (node.getRiskScore() > 0) {
            steps.add("3. Эксплуатация высокого риска (riskScore=" + node.getRiskScore() + ")");
        } else {
            steps.add("3. Получение/модификация данных");
        }
        return steps;
    }

    private static void addUnique(List<String> target, String value) {
        if (target == null || value == null || value.isBlank()) {
            return;
        }
        if (!target.contains(value)) {
            target.add(value);
        }
    }

    private static boolean looksLikePrivilegeField(String name) {
        if (name == null) {
            return false;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.contains("role") ||
            lower.contains("permission") ||
            lower.contains("scope") ||
            lower.contains("status") ||
            lower.contains("tier") ||
            lower.contains("level") ||
            lower.contains("group") ||
            lower.contains("profile") ||
            lower.contains("plan") ||
            lower.contains("access") ||
            lower.contains("action") ||
            lower.contains("operation") ||
            lower.contains("mode") ||
            lower.contains("privilege");
    }
    
    private static void addBolaChains(AttackSurface surface, OpenAPI openAPI,
                                      ContextAnalyzer.APIContext context) {
        List<CorrelationEngine.BOLAChain> bolaChains = CorrelationEngine.findBOLAChains(openAPI);
        if (bolaChains.isEmpty()) {
            return;
        }
        for (CorrelationEngine.BOLAChain bolaChain : bolaChains) {
            AttackChain chain = new AttackChain();
            chain.setType("BOLA");
            chain.setTarget(bolaChain.getResourceEndpoint());
            chain.setExploitable(bolaChain.isExploitable());

            String dataSensitivityLevel = null;
            List<String> sensitiveFields = new ArrayList<>();
            Operation resourceOp = resolveOperation(openAPI, bolaChain.getResourceEndpoint(), "GET");
            if (resourceOp != null) {
                DataSensitivity sensitivity =
                    CorrelationEngine.analyzeResponseSensitivity(resourceOp);
                dataSensitivityLevel = sensitivity.getLevel();
                sensitiveFields.addAll(sensitivity.getFields());
            }

            chain.setDataSensitivityLevel(dataSensitivityLevel);
            chain.setSensitiveFields(sensitiveFields);

            String severity = bolaChain.getSeverity() != null ? bolaChain.getSeverity() : "HIGH";
            chain.setSeverity(adjustSeverity(severity, context, bolaChain.isExploitable(), dataSensitivityLevel));
            chain.setSteps(bolaChain.getSteps());

            chain.getMetadata().put("listEndpoint", bolaChain.getListEndpoint());
            chain.getMetadata().put("listHasAuth", bolaChain.isListHasAuth() ? "Требуется аутентификация" : "Без аутентификации");
            chain.getMetadata().put("resourceHasAuth", bolaChain.isResourceHasAuth() ? "Требуется аутентификация" : "Без аутентификации");

            surface.getAttackChains().add(chain);
        }
    }

    private static Operation resolveOperation(OpenAPI openAPI, String path, String method) {
        if (openAPI == null || path == null || method == null || openAPI.getPaths() == null) {
            return null;
        }
        PathItem item = openAPI.getPaths().get(path);
        if (item == null) {
            return null;
        }
        return switch (method.toUpperCase(Locale.ROOT)) {
            case "GET" -> item.getGet();
            case "POST" -> item.getPost();
            case "PUT" -> item.getPut();
            case "DELETE" -> item.getDelete();
            case "PATCH" -> item.getPatch();
            default -> null;
        };
    }

    private static String adjustSeverity(String baseSeverity,
                                         ContextAnalyzer.APIContext context,
                                         boolean exploitable,
                                         String dataSensitivityLevel) {
        int level = severityToLevel(baseSeverity);
        if (isCriticalContext(context)) {
            level = Math.max(0, level - 1);
        }
        if (exploitable) {
            level = Math.max(0, level - 1);
        }
        if (dataSensitivityLevel != null) {
            String norm = dataSensitivityLevel.toUpperCase(Locale.ROOT);
            if ("CRITICAL".equals(norm)) {
                level = Math.max(0, level - 1);
            } else if ("HIGH".equals(norm)) {
                level = Math.max(0, level - 1);
            }
        }
        return levelToSeverity(level);
    }

    private static int severityToLevel(String severity) {
        if (severity == null) {
            return 2;
        }
        return switch (severity.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> 0;
            case "HIGH" -> 1;
            case "MEDIUM" -> 2;
            case "LOW" -> 3;
            default -> 2;
        };
    }

    private static String levelToSeverity(int level) {
        return switch (Math.max(0, Math.min(level, 3))) {
            case 0 -> "CRITICAL";
            case 1 -> "HIGH";
            case 2 -> "MEDIUM";
            default -> "LOW";
        };
    }

    private static boolean isCriticalContext(ContextAnalyzer.APIContext context) {
        if (context == null) {
            return false;
        }
        return switch (context) {
            case BANKING, GOVERNMENT, HEALTHCARE, TELECOM, AUTOMOTIVE -> true;
            default -> false;
        };
    }
    
    @Data
    public static class AttackSurface {
        private Map<String, EndpointNode> nodes = new HashMap<>();
        private List<Relationship> relationships = new ArrayList<>();
        private List<String> entryPoints = new ArrayList<>();
        private List<EntryPoint> entryPointDetails = new ArrayList<>();
        private List<AttackChain> attackChains = new ArrayList<>();
        private String context;
    }
    
    @Data
    public static class EndpointNode {
        private String path;
        private String method;
        private String type; // LIST, RESOURCE, CREATE, ACTION
        private boolean requiresAuth;
        private boolean hasParameters;
        private boolean critical;
        private boolean consentRequired;
        private boolean strongAuth;
        private boolean openBanking;
        private int riskScore;
        private String severity;
        private String dataSensitivityLevel;
        private List<String> sensitiveFields = new ArrayList<>();
        private List<String> signals = new ArrayList<>();
        private List<String> ssrfParameters = new ArrayList<>();
        private List<String> injectionParameters = new ArrayList<>();
        private List<String> privilegeParameters = new ArrayList<>();
    }
    
    @Data
    public static class Relationship {
        private String from;
        private String to;
        private String type;
    }
    
    @Data
    public static class AttackChain {
        private List<String> steps;
        private String severity;
        private String target;
        private String type;
        private boolean exploitable;
        private String dataSensitivityLevel;
        private List<String> sensitiveFields = new ArrayList<>();
        private Map<String, String> metadata = new LinkedHashMap<>();
        private int riskScore;
        private List<String> signals = new ArrayList<>();
    }

    @Data
    public static class EntryPoint {
        private String key;
        private String method;
        private String path;
        private boolean requiresAuth;
        private boolean strongAuth;
        private boolean consentRequired;
        private boolean openBanking;
        private int riskScore;
        private String severity;
        private String dataSensitivityLevel;
        private boolean weakProtection;
        private boolean highRisk;
        private List<String> signals = new ArrayList<>();
        private List<String> sensitiveFields = new ArrayList<>();
        private List<String> ssrfParameters = new ArrayList<>();
        private List<String> injectionParameters = new ArrayList<>();
        private List<String> privilegeParameters = new ArrayList<>();
    }
}

