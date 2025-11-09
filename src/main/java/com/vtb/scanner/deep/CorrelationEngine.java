package com.vtb.scanner.deep;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.Schema;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * Движок корреляционного анализа
 * Находит связи между эндпоинтами для обнаружения BOLA цепочек
 */
@Slf4j
public class CorrelationEngine {
    
    /**
     * Найти BOLA цепочки - УЛУЧШЕННАЯ ЭВРИСТИКА
     * 
     * Не просто LIST → RESOURCE, а 5 типов цепочек:
     * 1. Прямая: /users → /users/{id}
     * 2. Вложенная: /accounts/{id}/transactions → /accounts/{id}/transactions/{txId}
     * 3. Cross-resource: /users → /orders/{userId}
     * 4. Batch: /users/batch → /users/{id}
     * 5. Search: /users/search → /users/{id}
     */
    public static List<BOLAChain> findBOLAChains(OpenAPI openAPI) {
        List<BOLAChain> chains = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) {
            return chains;
        }
        
        Map<String, PathItem> paths = openAPI.getPaths();
        List<String> resourcePaths = new ArrayList<>();
        List<String> listPaths = new ArrayList<>();
        
        // Классифицируем эндпоинты
        for (String path : paths.keySet()) {
            if (path.contains("{")) {
                resourcePaths.add(path);
            } else {
                listPaths.add(path);
            }
        }
        
        // Тип 1: Прямая связь /users → /users/{id}
        for (String resourcePath : resourcePaths) {
            // КРИТИЧНО: Защита от StringIndexOutOfBoundsException
            int lastSlashIndex = resourcePath.lastIndexOf("/");
            if (lastSlashIndex <= 0) {
                continue; // Нет слеша или путь начинается со слеша - пропускаем
            }
            
            String basePath = resourcePath.substring(0, lastSlashIndex);
            
            if (paths.containsKey(basePath)) {
                chains.addAll(checkPair(basePath, resourcePath, paths));
            }
        }
        
        // Тип 2: Поиск по семантике (search, find, list)
        for (String listPath : listPaths) {
            String lowerPath = listPath.toLowerCase();
            
            if (lowerPath.contains("search") || lowerPath.contains("find") || 
                lowerPath.contains("list") || lowerPath.contains("all")) {
                
                // Ищем связанные ресурсы
                String resourceType = extractResourceType(listPath);
                
                for (String resourcePath : resourcePaths) {
                    if (resourcePath.toLowerCase().contains(resourceType)) {
                        chains.addAll(checkPair(listPath, resourcePath, paths));
                    }
                }
            }
        }
        
        // Тип 3: Batch операции
        for (String listPath : listPaths) {
            if (listPath.contains("batch") || listPath.contains("bulk")) {
                String resourceType = extractResourceType(listPath);
                
                for (String resourcePath : resourcePaths) {
                    if (resourcePath.toLowerCase().contains(resourceType)) {
                        chains.addAll(checkPair(listPath, resourcePath, paths));
                    }
                }
            }
        }
        
        // Тип 4: Вложенные ресурсы (nested)
        // /accounts/{id}/transactions → /accounts/{id}/transactions/{txId}
        for (String resourcePath1 : resourcePaths) {
            // КРИТИЧНО: Защита от StringIndexOutOfBoundsException
            int lastBraceIndex = resourcePath1.lastIndexOf("}");
            if (lastBraceIndex <= 0) {
                continue; // Нет закрывающей скобки - пропускаем
            }
            
            String basePath = resourcePath1.substring(0, lastBraceIndex);
            
            for (String resourcePath2 : resourcePaths) {
                if (!resourcePath1.equals(resourcePath2) && resourcePath2.startsWith(basePath)) {
                    // resourcePath2 является вложенным в resourcePath1
                    chains.addAll(checkPair(resourcePath1, resourcePath2, paths));
                }
            }
        }
        
        // Тип 5: Cross-resource (разные ресурсы, но связанные ID)
        // /users → /orders/{userId}, /posts/{userId}
        for (String listPath : listPaths) {
            String resourceType = extractResourceType(listPath);
            
            for (String resourcePath : resourcePaths) {
                String lowerResourcePath = resourcePath.toLowerCase();
                // Ищем параметры с именем другого ресурса
                // Например: /orders/{userId} связан с /users
                if (lowerResourcePath.contains("{" + resourceType.toLowerCase() + "id}") ||
                    lowerResourcePath.contains("{" + resourceType.toLowerCase() + "_id}")) {
                    chains.addAll(checkPair(listPath, resourcePath, paths));
                }
            }
        }
        
        log.info("Найдено BOLA цепочек: {} (5 типов проверок)", chains.size());
        return chains;
    }
    
    /**
     * Проверка пары эндпоинтов на BOLA цепочку
     */
    private static List<BOLAChain> checkPair(String listPath, String resourcePath, Map<String, PathItem> paths) {
        List<BOLAChain> chains = new ArrayList<>();
        
        PathItem listEndpoint = paths.get(listPath);
        PathItem resourceEndpoint = paths.get(resourcePath);
        
        if (listEndpoint == null || resourceEndpoint == null) {
            return chains;
        }
        
        // Проверяем GET на обоих
        if (listEndpoint.getGet() != null && resourceEndpoint.getGet() != null) {
            Operation listOp = listEndpoint.getGet();
            Operation resourceOp = resourceEndpoint.getGet();
            
            boolean listHasAuth = hasAuth(listOp);
            boolean resourceHasAuth = hasAuth(resourceOp);
            
            // BOLA chain если resource без auth
            if (!resourceHasAuth) {
                BOLAChain chain = new BOLAChain();
                chain.setListEndpoint(listPath);
                chain.setResourceEndpoint(resourcePath);
                chain.setListHasAuth(listHasAuth);
                chain.setResourceHasAuth(false);
                chain.setSeverity(listHasAuth ? "HIGH" : "CRITICAL");
                chain.setExploitable(true);
                chain.setSteps(Arrays.asList(
                    "1. GET " + listPath + " - получить список ID",
                    "2. Выбрать чужой ID из ответа",
                    "3. GET " + resourcePath + " - получить чужие данные (BOLA!)"
                ));
                
                chains.add(chain);
                log.info("🔗 Найдена BOLA цепочка: {} → {}", listPath, resourcePath);
            }
            
            // Inconsistency если list защищен, а resource нет
            if (listHasAuth && !resourceHasAuth) {
                log.warn("Несогласованность: {} защищен, но {} нет!", listPath, resourcePath);
            }
        }
        
        return chains;
    }
    
    /**
     * Извлечь тип ресурса из пути
     * /api/users/search → users
     */
    private static String extractResourceType(String path) {
        String[] parts = path.split("/");
        for (String part : parts) {
            if (!part.isEmpty() && 
                !part.equals("api") && 
                !part.equals("v1") && 
                !part.equals("v2") &&
                !part.contains("search") &&
                !part.contains("list") &&
                !part.contains("all") &&
                !part.contains("batch")) {
                return part;
            }
        }
        return "";
    }
    
    /**
     * Анализ чувствительности данных в response schema
     */
    public static DataSensitivity analyzeResponseSensitivity(Operation operation) {
        DataSensitivity sensitivity = new DataSensitivity();
        
        if (operation.getResponses() == null) {
            return sensitivity;
        }
        
        var response200 = operation.getResponses().get("200");
        if (response200 == null || response200.getContent() == null) {
            return sensitivity;
        }
        
        var jsonContent = response200.getContent().get("application/json");
        if (jsonContent == null || jsonContent.getSchema() == null) {
            return sensitivity;
        }
        
        Schema schema = jsonContent.getSchema();
        
        // Анализируем поля
        if (schema.getProperties() != null) {
            @SuppressWarnings("rawtypes")
            Map properties = schema.getProperties();
            
            for (Object key : properties.keySet()) {
                String fieldName = key.toString().toLowerCase();
                
                // КРИТИЧНО чувствительные (ФЗ-152)
                if (fieldName.contains("passport") || fieldName.contains("паспорт")) {
                    sensitivity.setCritical(true);
                    sensitivity.getFields().add(key.toString() + " (паспорт - ФЗ-152!)");
                }
                else if (fieldName.contains("inn") || fieldName.contains("snils") || 
                         fieldName.contains("инн") || fieldName.contains("снилс")) {
                    sensitivity.setHigh(true);
                    sensitivity.getFields().add(key.toString() + " (ПДн)");
                }
                // Персональные данные
                else if (fieldName.contains("email") || fieldName.contains("phone") || 
                         fieldName.contains("name") || fieldName.contains("address")) {
                    sensitivity.setMedium(true);
                    sensitivity.getFields().add(key.toString());
                }
            }
        }
        
        // Определяем уровень
        if (sensitivity.isCritical()) {
            sensitivity.setLevel("CRITICAL");
        } else if (sensitivity.isHigh()) {
            sensitivity.setLevel("HIGH");
        } else if (sensitivity.isMedium()) {
            sensitivity.setLevel("MEDIUM");
        } else {
            sensitivity.setLevel("LOW");
        }
        
        return sensitivity;
    }
    
    private static boolean hasAuth(Operation operation) {
        return operation.getSecurity() != null && !operation.getSecurity().isEmpty();
    }
    
    @Data
    public static class BOLAChain {
        private String listEndpoint;
        private String resourceEndpoint;
        private boolean listHasAuth;
        private boolean resourceHasAuth;
        private String severity;
        private boolean exploitable;
        private List<String> steps;
    }
    
    @Data
    public static class DataSensitivity {
        private String level = "LOW";
        private boolean critical = false;
        private boolean high = false;
        private boolean medium = false;
        private List<String> fields = new ArrayList<>();
    }
}

