package com.vtb.scanner.heuristics;

import com.vtb.scanner.models.Severity;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * Умный анализатор структуры API
 * Вычисляет risk scores, health score, находит аномалии
 */
@Slf4j
public class SmartAnalyzer {
    
    /**
     * Анализ структуры API
     * @return Map с ключами: apiHealthScore, totalEndpoints, withAuth, withoutAuth
     */
    public static Map<String, Object> analyzeAPIStructure(OpenAPI openAPI) {
        Map<String, Object> result = new HashMap<>();
        
        if (openAPI == null || openAPI.getPaths() == null) {
            result.put("apiHealthScore", 0);
            result.put("totalEndpoints", 0);
            result.put("withAuth", 0);
            result.put("withoutAuth", 0);
            return result;
        }
        
        int totalEndpoints = 0;
        int withAuth = 0;
        int withoutAuth = 0;
        
        for (PathItem pathItem : openAPI.getPaths().values()) {
            List<Operation> operations = getAllOperations(pathItem);
            totalEndpoints += operations.size();
            
            for (Operation op : operations) {
                if (hasSecurity(op, openAPI)) {
                    withAuth++;
                } else {
                    withoutAuth++;
                }
            }
        }
        
        // Health Score: процент эндпоинтов с auth
        long healthScore = totalEndpoints > 0 ? 
            (withAuth * 100L / totalEndpoints) : 0;
        
        result.put("apiHealthScore", healthScore);
        result.put("totalEndpoints", totalEndpoints);
        result.put("withAuth", withAuth);
        result.put("withoutAuth", withoutAuth);
        
        return result;
    }
    
    /**
     * Найти аномалии в структуре API
     */
    public static List<String> findAnomalies(OpenAPI openAPI) {
        List<String> anomalies = new ArrayList<>();
        
        if (openAPI == null || openAPI.getPaths() == null) {
            return anomalies;
        }
        
        Map<String, Object> structure = analyzeAPIStructure(openAPI);
        long healthScore = ((Number) structure.get("apiHealthScore")).longValue();
        int totalEndpoints = (Integer) structure.get("totalEndpoints");
        int withoutAuth = (Integer) structure.get("withoutAuth");
        
        // Низкий health score
        if (healthScore < 50 && totalEndpoints > 0) {
            anomalies.add(String.format(
                "Низкий уровень безопасности: только %d%% эндпоинтов защищены аутентификацией",
                healthScore
            ));
        }
        
        // Много эндпоинтов без auth
        if (withoutAuth > totalEndpoints * 0.5 && totalEndpoints > 5) {
            anomalies.add(String.format(
                "Большое количество незащищенных эндпоинтов: %d из %d",
                withoutAuth, totalEndpoints
            ));
        }
        
        // Проверка на debug endpoints
        for (String path : openAPI.getPaths().keySet()) {
            String lowerPath = path.toLowerCase();
            if (lowerPath.contains("debug") || lowerPath.contains("test") || 
                lowerPath.contains("dev") || lowerPath.contains("admin")) {
                PathItem pathItem = openAPI.getPaths().get(path);
                if (hasAnyOperation(pathItem)) {
                    Operation op = getFirstOperation(pathItem);
                    if (!hasSecurity(op, openAPI)) {
                        anomalies.add(String.format(
                            "Debug/admin эндпоинт без защиты: %s", path
                        ));
                    }
                }
            }
        }
        
        return anomalies;
    }
    
    /**
     * Вычислить risk score для операции
     * @return score 0-250
     */
    public static int calculateRiskScore(String path, String method, Operation operation, OpenAPI openAPI) {
        int score = 0;
        
        if (path == null || method == null || operation == null) {
            return score;
        }
        
        String pathLower = path.toLowerCase();
        String methodUpper = method.toUpperCase();
        
        // Метод DELETE - высокий риск
        if ("DELETE".equals(methodUpper)) {
            score += 40;
        }
        
        // Метод PUT/PATCH - средний риск
        if ("PUT".equals(methodUpper) || "PATCH".equals(methodUpper)) {
            score += 30;
        }
        
        // Критичные пути
        if (pathLower.contains("admin") || pathLower.contains("delete") || 
            pathLower.contains("remove") || pathLower.contains("destroy")) {
            score += 50;
        }
        
        // ID параметры в пути
        if (path.contains("{id}") || path.contains("{ID}") || 
            EnhancedRules.isIDParameter(path)) {
            score += 30;
        }
        
        // Нет аутентификации
        if (!hasSecurity(operation, openAPI)) {
            score += 60;
        }
        
        // Операции с деньгами
        if (pathLower.contains("payment") || pathLower.contains("transfer") || 
            pathLower.contains("withdraw") || pathLower.contains("deposit")) {
            score += 50;
        }
        
        // Персональные данные
        if (pathLower.contains("user") || pathLower.contains("account") || 
            pathLower.contains("profile")) {
            score += 20;
        }
        
        // SQL injection риски
        if (operation.getParameters() != null) {
            for (var param : operation.getParameters()) {
                if (EnhancedRules.isSQLInjectionRisk(param)) {
                    score += 40;
                }
            }
        }
        
        return Math.min(250, score);
    }
    
    /**
     * Преобразовать risk score в Severity
     */
    public static Severity severityFromRiskScore(int riskScore) {
        if (riskScore >= 150) {
            return Severity.CRITICAL;
        } else if (riskScore >= 100) {
            return Severity.HIGH;
        } else if (riskScore >= 50) {
            return Severity.MEDIUM;
        } else if (riskScore >= 20) {
            return Severity.LOW;
        } else {
            return Severity.INFO;
        }
    }
    
    // ═══════════════════════════════════════════════════════════════
    // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
    // ═══════════════════════════════════════════════════════════════
    
    private static List<Operation> getAllOperations(PathItem pathItem) {
        List<Operation> operations = new ArrayList<>();
        if (pathItem.getGet() != null) operations.add(pathItem.getGet());
        if (pathItem.getPost() != null) operations.add(pathItem.getPost());
        if (pathItem.getPut() != null) operations.add(pathItem.getPut());
        if (pathItem.getDelete() != null) operations.add(pathItem.getDelete());
        if (pathItem.getPatch() != null) operations.add(pathItem.getPatch());
        if (pathItem.getOptions() != null) operations.add(pathItem.getOptions());
        if (pathItem.getHead() != null) operations.add(pathItem.getHead());
        return operations;
    }
    
    private static boolean hasSecurity(Operation operation, OpenAPI openAPI) {
        if (operation == null) return false;
        
        // Проверка локальной security
        if (operation.getSecurity() != null && !operation.getSecurity().isEmpty()) {
            return true;
        }
        
        // Проверка глобальной security
        if (openAPI != null && openAPI.getSecurity() != null && 
            !openAPI.getSecurity().isEmpty()) {
            return true;
        }
        
        return false;
    }
    
    private static boolean hasAnyOperation(PathItem pathItem) {
        return pathItem.getGet() != null || pathItem.getPost() != null || 
               pathItem.getPut() != null || pathItem.getDelete() != null ||
               pathItem.getPatch() != null;
    }
    
    private static Operation getFirstOperation(PathItem pathItem) {
        if (pathItem.getGet() != null) return pathItem.getGet();
        if (pathItem.getPost() != null) return pathItem.getPost();
        if (pathItem.getPut() != null) return pathItem.getPut();
        if (pathItem.getDelete() != null) return pathItem.getDelete();
        if (pathItem.getPatch() != null) return pathItem.getPatch();
        return null;
    }
}

