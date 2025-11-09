package com.vtb.scanner.scanners;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.deep.CorrelationEngine;
import com.vtb.scanner.knowledge.CVEMapper;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.util.AccessControlHeuristics;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

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
        log.info("Запуск ГЛУБОКОГО BOLA Scanner...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        // УРОВЕНЬ 1: Базовая проверка эндпоинтов
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            vulnerabilities.addAll(checkPathForBOLA(path, pathItem, parser, openAPI));
        }
        
        // УРОВЕНЬ 2: ГЛУБОКИЙ - Корреляционный анализ (BOLA цепочки)
        log.info("🔗 Запуск корреляционного анализа (BOLA chains)...");
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
    private List<Vulnerability> checkPathForBOLA(String path, PathItem pathItem, OpenAPIParser parser, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Проверяем есть ли в пути параметры-идентификаторы
        boolean hasIdInPath = containsIdParameter(path);
        
        // Проверяем GET
        if (pathItem.getGet() != null) {
            vulnerabilities.addAll(checkOperation(path, "GET", pathItem.getGet(), hasIdInPath, parser, openAPI));
        }
        
        // Проверяем PUT/PATCH/DELETE - особо опасные для BOLA
        if (pathItem.getPut() != null) {
            vulnerabilities.addAll(checkOperation(path, "PUT", pathItem.getPut(), hasIdInPath, parser, openAPI));
        }
        if (pathItem.getPatch() != null) {
            vulnerabilities.addAll(checkOperation(path, "PATCH", pathItem.getPatch(), hasIdInPath, parser, openAPI));
        }
        if (pathItem.getDelete() != null) {
            vulnerabilities.addAll(checkOperation(path, "DELETE", pathItem.getDelete(), hasIdInPath, parser, openAPI));
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка конкретной операции
     */
    private List<Vulnerability> checkOperation(String path, String method, Operation operation, 
                                                boolean hasIdInPath, OpenAPIParser parser, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (isCatalogResource(path, operation)) {
            return vulnerabilities;
        }

        // ИСПОЛЬЗУЕМ SmartAnalyzer!
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
            path, method, operation, openAPI);
        Severity smartSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
        
        boolean hasExplicitAccessControl = AccessControlHeuristics.hasExplicitAccessControl(operation, path);
        
        // Если эндпоинт содержит ID и не требует аутентификации - критичная BOLA
        if (hasIdInPath && !parser.requiresAuthentication(operation)) {
            // Severity: макс из SmartAnalyzer и CRITICAL (т.к. BOLA без auth!)
            Severity severity = (smartSeverity == Severity.CRITICAL || riskScore > 100) ? 
                Severity.CRITICAL : Severity.HIGH;
            
            vulnerabilities.add(createBolaVulnerability(
                path, method, 
                severity,
                riskScore,
                "Эндпоинт с параметром ID не защищен аутентификацией",
                "Любой пользователь может получить доступ к объектам других пользователей, " +
                "просто изменяя ID в запросе",
                "Добавьте обязательную аутентификацию и проверку владельца объекта"
            ));
        }
        // Если есть ID но нет проверки авторизации
        else if (hasIdInPath && parser.requiresAuthentication(operation)) {
            if (!hasExplicitAccessControl && !mentionsOwnership(operation)) {
                vulnerabilities.add(createBolaVulnerability(
                    path, method,
                    Severity.HIGH,
                    riskScore,
                    "Эндпоинт с параметром ID может не проверять владельца объекта",
                    "В спецификации не указана проверка прав доступа к объекту. " +
                    "Убедитесь, что API проверяет, принадлежит ли объект текущему пользователю",
                    "Добавьте проверку владельца объекта перед выполнением операции"
                ));
            }
        }
        
        // Проверяем query параметры
        if (operation.getParameters() != null) {
            for (Parameter param : operation.getParameters()) {
                // ИСПОЛЬЗУЕМ EnhancedRules!
                if (param.getName() != null && com.vtb.scanner.heuristics.EnhancedRules.isIDParameter(param.getName())) {
                    if (!parser.requiresAuthentication(operation)) {
                        vulnerabilities.add(createBolaVulnerability(
                            path, method,
                            Severity.HIGH,
                            riskScore,
                            "Параметр '" + param.getName() + "' может быть использован для BOLA атаки",
                            "Query параметр содержит идентификатор, но эндпоинт не защищен аутентификацией",
                            "Добавьте аутентификацию и проверку прав доступа"
                        ));
                    }
                }
            }
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверить содержит ли путь ID параметр
     */
    private boolean containsIdParameter(String path) {
        // ИСПОЛЬЗУЕМ EnhancedRules!
        return com.vtb.scanner.heuristics.EnhancedRules.isIDParameter(path) || 
               path.contains("{id}") || 
               path.contains("{ID}") ||
               path.contains("/{") && path.contains("}"); // любой path parameter
    }
    
    private boolean mentionsOwnership(Operation operation) {
        if (operation == null) {
            return false;
        }
        String text = ((operation.getSummary() != null ? operation.getSummary() : "") +
            (operation.getDescription() != null ? operation.getDescription() : "")).toLowerCase();
        return text.contains("owner") ||
               text.contains("ownership") ||
               text.contains("владел") ||
               text.contains("принадлеж") ||
               text.contains("authorization");
    }
    
    /**
     * Создать объект уязвимости BOLA
     * 
     * С ПОЛНЫМ НАБОРОМ: CVE/CWE + Confidence + Priority + Impact + RiskScore!
     */
    private Vulnerability createBolaVulnerability(String endpoint, String method, Severity severity,
                                                   int riskScore,
                                                   String title, String description, String recommendation) {
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
            .evidence("Обнаружен эндпоинт с идентификатором объекта без должной защиты. Risk Score: " + riskScore)
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
}

