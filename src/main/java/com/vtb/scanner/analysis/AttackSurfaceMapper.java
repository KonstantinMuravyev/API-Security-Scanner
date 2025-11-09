package com.vtb.scanner.analysis;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

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
        
        Map<String, EndpointNode> nodes = new HashMap<>();
        
        // 1. Создаем узлы для каждого эндпоинта
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // Для каждого метода
            if (pathItem.getGet() != null) {
                String key = "GET " + path;
                nodes.put(key, analyzeEndpoint(path, "GET", pathItem.getGet()));
            }
            if (pathItem.getPost() != null) {
                String key = "POST " + path;
                nodes.put(key, analyzeEndpoint(path, "POST", pathItem.getPost()));
            }
            if (pathItem.getPut() != null) {
                String key = "PUT " + path;
                nodes.put(key, analyzeEndpoint(path, "PUT", pathItem.getPut()));
            }
            if (pathItem.getDelete() != null) {
                String key = "DELETE " + path;
                nodes.put(key, analyzeEndpoint(path, "DELETE", pathItem.getDelete()));
            }
        }
        
        surface.setNodes(nodes);
        
        // 2. Находим связи между эндпоинтами
        surface.setRelationships(findRelationships(nodes));
        
        // 3. Определяем критичные точки входа
        surface.setEntryPoints(findEntryPoints(nodes));
        
        // 4. Находим цепочки атак
        surface.setAttackChains(findAttackChains(nodes, openAPI));
        
        log.info("Attack Surface: {} эндпоинтов, {} связей, {} точек входа, {} цепочек атак",
            nodes.size(), surface.getRelationships().size(), 
            surface.getEntryPoints().size(), surface.getAttackChains().size());
        
        return surface;
    }
    
    private static EndpointNode analyzeEndpoint(String path, String method, Operation operation) {
        EndpointNode node = new EndpointNode();
        
        // КРИТИЧНО: Защита от NPE
        node.setPath(path != null ? path : "");
        node.setMethod(method != null ? method : "");
        
        if (operation != null) {
            node.setRequiresAuth(operation.getSecurity() != null && !operation.getSecurity().isEmpty());
            node.setHasParameters(operation.getParameters() != null && !operation.getParameters().isEmpty());
        } else {
            node.setRequiresAuth(false);
            node.setHasParameters(false);
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
        
        // Критичность
        node.setCritical(
            !node.isRequiresAuth() ||
            "DELETE".equals(safeMethod) ||
            safePath.toLowerCase().contains("admin")
        );
        
        return node;
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
    
    private static List<String> findEntryPoints(Map<String, EndpointNode> nodes) {
        List<String> entryPoints = new ArrayList<>();
        
        for (Map.Entry<String, EndpointNode> entry : nodes.entrySet()) {
            EndpointNode node = entry.getValue();
            
            // Точки входа - эндпоинты без auth
            if (!node.isRequiresAuth()) {
                entryPoints.add(entry.getKey());
            }
        }
        
        return entryPoints;
    }
    
    private static List<AttackChain> findAttackChains(Map<String, EndpointNode> nodes, OpenAPI openAPI) {
        List<AttackChain> chains = new ArrayList<>();
        
        // Ищем потенциальные цепочки атак
        // Например: /login (без rate limit) → получить токен → /admin (BOLA)
        
        for (Map.Entry<String, EndpointNode> entry : nodes.entrySet()) {
            EndpointNode node = entry.getValue();
            
            // Если это критичный эндпоинт без auth
            if (node.isCritical() && !node.isRequiresAuth()) {
                AttackChain chain = new AttackChain();
                chain.setSteps(Arrays.asList(
                    "1. Прямой доступ к " + node.getPath(),
                    "2. Эксплуатация (нет аутентификации)",
                    "3. Получение/модификация данных"
                ));
                chain.setSeverity("CRITICAL");
                chain.setTarget(entry.getKey());
                chains.add(chain);
            }
            
            // Цепочка: List endpoint → BOLA в Resource
            if (node.getType().equals("RESOURCE") && !node.isRequiresAuth()) {
                // КРИТИЧНО: Защита от NPE при substring
                String nodePath = node.getPath();
                if (nodePath != null && nodePath.contains("/")) {
                    String basePath = nodePath.substring(0, nodePath.lastIndexOf("/"));
                    
                    if (basePath != null && openAPI.getPaths() != null && 
                        openAPI.getPaths().containsKey(basePath)) {
                        AttackChain chain = new AttackChain();
                        chain.setSteps(Arrays.asList(
                            "1. GET " + basePath + " - получить список ID",
                            "2. Выбрать чужой ID",
                            "3. " + node.getMethod() + " " + node.getPath() + " - BOLA атака"
                        ));
                        chain.setSeverity("HIGH");
                        chain.setTarget(entry.getKey());
                        chains.add(chain);
                    }
                }
            }
        }
        
        return chains;
    }
    
    @Data
    public static class AttackSurface {
        private Map<String, EndpointNode> nodes = new HashMap<>();
        private List<Relationship> relationships = new ArrayList<>();
        private List<String> entryPoints = new ArrayList<>();
        private List<AttackChain> attackChains = new ArrayList<>();
    }
    
    @Data
    public static class EndpointNode {
        private String path;
        private String method;
        private String type; // LIST, RESOURCE, CREATE, ACTION
        private boolean requiresAuth;
        private boolean hasParameters;
        private boolean critical;
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
    }
}

