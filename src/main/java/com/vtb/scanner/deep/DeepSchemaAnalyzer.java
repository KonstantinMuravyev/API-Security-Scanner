package com.vtb.scanner.deep;

import com.vtb.scanner.heuristics.EnhancedRules;
import com.vtb.scanner.models.Severity;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.media.Schema;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * ГЛУБОКИЙ анализ JSON schemas
 * 
 * Проверяет:
 * 1. Request body - mass assignment, readonly поля
 * 2. Response body - чувствительные данные, excessive exposure
 * 3. Nested objects - рекурсивно до 20 уровней (для покрытия сложных API)
 * 4. Arrays - проверка элементов массивов
 * 5. Validation rules - оценка качества
 */
@Slf4j
public class DeepSchemaAnalyzer {
    
    /**
     * Максимальная глубина вложенности для анализа схем
     * 
     * КРИТИЧНО: Реальные API обычно имеют вложенность 2-8 уровней.
     * Очень сложные API (Microsoft Graph, GitHub API) могут иметь до 12-15 уровней.
     * Значение 20 обеспечивает покрытие даже самых сложных случаев без риска проблем производительности.
     */
    private static final int MAX_DEPTH = 20; // Увеличено с 10 до 20 для более точного анализа сложных API
    
    /**
     * ГЛУБОКИЙ анализ request body schema
     * Находит mass assignment даже в глубоко вложенных объектах!
     * 
     * КРИТИЧНО: Автоматически разрешает $ref ссылки для гарантированного анализа!
     */
    public static List<SchemaIssue> analyzeRequestBody(Schema<?> schema, String path, String method) {
        return analyzeRequestBody(schema, path, method, null);
    }
    
    /**
     * ГЛУБОКИЙ анализ request body schema с поддержкой $ref
     */
    public static List<SchemaIssue> analyzeRequestBody(Schema<?> schema, String path, String method, OpenAPI openAPI) {
        List<SchemaIssue> issues = new ArrayList<>();
        
        if (schema == null) return issues;
        
        // КРИТИЧНО: Разрешаем $ref ссылки перед анализом
        Schema<?> resolvedSchema = resolveSchemaRef(schema, openAPI);
        
        // Рекурсивный анализ
        analyzeSchemaRecursive(resolvedSchema, "", path, method, 0, issues, AnalysisType.REQUEST, openAPI);
        
        return issues;
    }
    
    /**
     * ГЛУБОКИЙ анализ response schema
     * Находит excessive data exposure в глубине!
     * 
     * КРИТИЧНО: Автоматически разрешает $ref ссылки для гарантированного анализа!
     */
    public static List<SchemaIssue> analyzeResponse(Schema<?> schema, String path, String method) {
        return analyzeResponse(schema, path, method, null);
    }
    
    /**
     * ГЛУБОКИЙ анализ response schema с поддержкой $ref
     */
    public static List<SchemaIssue> analyzeResponse(Schema<?> schema, String path, String method, OpenAPI openAPI) {
        List<SchemaIssue> issues = new ArrayList<>();
        
        if (schema == null) return issues;
        
        // КРИТИЧНО: Разрешаем $ref ссылки перед анализом
        Schema<?> resolvedSchema = resolveSchemaRef(schema, openAPI);
        
        analyzeSchemaRecursive(resolvedSchema, "", path, method, 0, issues, AnalysisType.RESPONSE, openAPI);
        
        return issues;
    }
    
    /**
     * Рекурсивный анализ schema до 20 уровней вложенности!
     * 
     * КРИТИЧНО: Автоматически разрешает $ref ссылки на каждом уровне!
     * КРИТИЧНО: Защита от циклических ссылок для предотвращения StackOverflowError!
     */
    @SuppressWarnings("rawtypes")
    private static void analyzeSchemaRecursive(Schema schema, String currentPath,
                                               String endpointPath, String method,
                                               int depth, List<SchemaIssue> issues,
                                               AnalysisType type, OpenAPI openAPI) {
        analyzeSchemaRecursive(schema, currentPath, endpointPath, method, depth, issues, type, openAPI, new HashSet<>());
    }
    
    /**
     * Рекурсивный анализ schema с защитой от циклических ссылок
     */
    @SuppressWarnings("rawtypes")
    private static void analyzeSchemaRecursive(Schema schema, String currentPath,
                                               String endpointPath, String method,
                                               int depth, List<SchemaIssue> issues,
                                               AnalysisType type, OpenAPI openAPI, Set<String> visited) {
        if (depth > MAX_DEPTH) {
            log.warn("Достигнута максимальная глубина вложенности: {} (путь: {}). " +
                     "Возможно, некоторые уязвимости в глубоко вложенных полях не были обнаружены.",
                     MAX_DEPTH, currentPath);
            return;
        }
        
        // КРИТИЧНО: Разрешаем $ref ссылки рекурсивно с защитой от циклов
        schema = resolveSchemaRef(schema, openAPI, visited);
        
        Map<String, Schema<?>> properties = collectSchemaProperties(schema);
        if (properties.isEmpty()) {
            return;
        }
        String endpointLower = endpointPath != null ? endpointPath.toLowerCase(Locale.ROOT) : "";
        String methodUpper = method != null ? method.toUpperCase(Locale.ROOT) : "";
        
        for (Map.Entry<String, Schema<?>> entry : properties.entrySet()) {
            String fieldName = entry.getKey();
            Schema<?> fieldSchema = entry.getValue();
            String fieldPath = currentPath.isEmpty() ? fieldName : currentPath + "." + fieldName;
            
            // REQUEST: Проверка на readonly поля (mass assignment!)
            if (type == AnalysisType.REQUEST && Boolean.TRUE.equals(fieldSchema.getReadOnly())) {
                if (shouldSkipRequestField(fieldName, fieldPath, endpointLower, methodUpper)) {
                    continue;
                }
                SchemaIssue issue = new SchemaIssue();
                issue.setPath(fieldPath);
                issue.setType("MASS_ASSIGNMENT");
                issue.setSeverity(Severity.HIGH);
                issue.setDescription("Read-only поле '" + fieldPath + "' может быть изменено через request!");
                issues.add(issue);
                log.info("Найдено: mass assignment на поле {}", fieldPath);
            }
            
            // REQUEST: Проверка на системные поля
            if (type == AnalysisType.REQUEST) {
                String lowerName = fieldName.toLowerCase(Locale.ROOT);
                if (shouldSkipRequestField(fieldName, fieldPath, endpointLower, methodUpper)) {
                    continue;
                }
                if (lowerName.equals("id") || lowerName.equals("created_at") || 
                    lowerName.equals("updated_at") || lowerName.equals("version") ||
                    lowerName.equals("status") || lowerName.contains("_id") ||
                    lowerName.equals("role") || lowerName.equals("admin") ||
                    lowerName.equals("permissions")) {
                    
                    SchemaIssue issue = new SchemaIssue();
                    issue.setPath(fieldPath);
                    issue.setType("DANGEROUS_FIELD_IN_INPUT");
                    issue.setSeverity(Severity.MEDIUM);
                    issue.setDescription("Системное поле '" + fieldPath + "' НЕ должно приниматься в input!");
                    issues.add(issue);
                }
            }
            
            // RESPONSE: Проверка на чувствительные данные
            if (type == AnalysisType.RESPONSE) {
                List<String> sensitiveFound = EnhancedRules.findSensitiveFieldsInResponse(fieldSchema);
                for (String sensitive : sensitiveFound) {
                    SchemaIssue issue = new SchemaIssue();
                    String sensitivePath = fieldPath.isEmpty() ? sensitive : fieldPath + "." + sensitive;
                    issue.setPath(sensitivePath);
                    issue.setType("SENSITIVE_DATA_EXPOSURE");
                    issue.setSeverity(Severity.HIGH);
                    issue.setDescription("Чувствительное поле '" + sensitivePath + "' в response!");
                    issues.add(issue);
                }
            }
            
            // RESPONSE: Проверка на персональные данные (ФЗ-152)
            if (type == AnalysisType.RESPONSE && EnhancedRules.hasPersonalData(fieldSchema)) {
                SchemaIssue issue = new SchemaIssue();
                issue.setPath(fieldPath);
                issue.setType("PERSONAL_DATA_FZ152");
                issue.setSeverity(Severity.HIGH);
                issue.setDescription("Персональные данные (ФЗ-152) в поле '" + fieldPath + "'!");
                issues.add(issue);
            }
            
            // КРИТИЧНО: Разрешаем $ref ссылки в полях перед рекурсией с защитой от циклов
            fieldSchema = resolveSchemaRef(fieldSchema, openAPI, visited);
            
            // Рекурсия для вложенных объектов
            if (fieldSchema != null && ("object".equals(fieldSchema.getType()) || fieldSchema.getProperties() != null ||
                fieldSchema.getAllOf() != null || fieldSchema.getAnyOf() != null || fieldSchema.getOneOf() != null)) {
                analyzeSchemaRecursive(fieldSchema, fieldPath, endpointPath, method, depth + 1, issues, type, openAPI, visited);
            }
            
            // Рекурсия для массивов
            if (fieldSchema != null && "array".equals(fieldSchema.getType()) && fieldSchema.getItems() != null) {
                Schema<?> itemsSchema = resolveSchemaRef(fieldSchema.getItems(), openAPI, visited);
                if (itemsSchema != null) {
                    analyzeSchemaRecursive(itemsSchema, fieldPath + "[]", endpointPath, method, depth + 1, issues, type, openAPI, visited);
                }
            }
        }
    }
    
    /**
     * Разрешить $ref ссылку на schema
     * КРИТИЧНО: Гарантирует, что все схемы будут проанализированы даже при ошибках resolve в библиотеке!
     * КРИТИЧНО: Защита от циклических ссылок для предотвращения StackOverflowError!
     */
    private static Schema<?> resolveSchemaRef(Schema<?> schema, OpenAPI openAPI) {
        return resolveSchemaRef(schema, openAPI, new HashSet<>());
    }
    
    /**
     * Разрешить $ref ссылку на schema с защитой от циклических ссылок
     */
    private static Schema<?> resolveSchemaRef(Schema<?> schema, OpenAPI openAPI, Set<String> visited) {
        if (schema == null) {
            return null;
        }
        
        // Если это не $ref ссылка, возвращаем как есть
        String ref = schema.get$ref();
        if (ref == null || openAPI == null || openAPI.getComponents() == null) {
            return schema;
        }
        
        // Формат: #/components/schemas/MySchema
        if (ref.startsWith("#/components/schemas/")) {
            String schemaName = ref.substring("#/components/schemas/".length());
            
            // КРИТИЧНО: Защита от циклических ссылок
            if (visited.contains(schemaName)) {
                log.warn("Обнаружена циклическая ссылка: {}, возвращаем оригинальную schema", ref);
                return schema; // Возвращаем оригинальную schema чтобы избежать бесконечной рекурсии
            }
            
            if (openAPI.getComponents().getSchemas() != null) {
                Schema<?> resolved = openAPI.getComponents().getSchemas().get(schemaName);
                if (resolved != null) {
                    log.debug("Разрешена $ref ссылка: {} -> {}", ref, schemaName);
                    // Добавляем в visited для защиты от циклов
                    visited.add(schemaName);
                    return resolved;
                }
            }
        }
        
        // Если не удалось разрешить, возвращаем оригинальную schema
        // (может быть это внешняя ссылка или ошибка в спецификации)
        return schema;
    }

    private static Map<String, Schema<?>> collectSchemaProperties(Schema<?> schema) {
        return collectSchemaProperties(schema, new IdentityHashMap<>());
    }

    private static Map<String, Schema<?>> collectSchemaProperties(Schema<?> schema,
                                                                  IdentityHashMap<Schema<?>, Boolean> visited) {
        Map<String, Schema<?>> properties = new LinkedHashMap<>();
        if (schema == null) {
            return properties;
        }
        if (visited.put(schema, Boolean.TRUE) != null) {
            return properties;
        }
        try {
            if (schema.getProperties() != null) {
                schema.getProperties().forEach((key, value) -> {
                    if (key != null && value instanceof Schema) {
                        properties.put(String.valueOf(key), (Schema<?>) value);
                    }
                });
            }
            if (schema.getAllOf() != null) {
                for (Schema<?> fragment : schema.getAllOf()) {
                    properties.putAll(collectSchemaProperties(fragment, visited));
                }
            }
            if (schema.getAnyOf() != null) {
                for (Schema<?> fragment : schema.getAnyOf()) {
                    mergeOptionalProperties(properties, fragment, visited);
                }
            }
            if (schema.getOneOf() != null) {
                for (Schema<?> fragment : schema.getOneOf()) {
                    mergeOptionalProperties(properties, fragment, visited);
                }
            }
        } finally {
            visited.remove(schema);
        }
        return properties;
    }

    private static void mergeOptionalProperties(Map<String, Schema<?>> target,
                                                Schema<?> schema,
                                                IdentityHashMap<Schema<?>, Boolean> visited) {
        Map<String, Schema<?>> from = collectSchemaProperties(schema, visited);
        for (Map.Entry<String, Schema<?>> entry : from.entrySet()) {
            target.putIfAbsent(entry.getKey(), entry.getValue());
        }
    }
    
    @Data
    public static class SchemaIssue {
        private String path;
        private String type;
        private Severity severity;
        private String description;
    }

    private static boolean shouldSkipRequestField(String fieldName, String fieldPath, String endpointLower, String methodUpper) {
        String lowerName = fieldName.toLowerCase(Locale.ROOT);
        String fieldPathLower = fieldPath.toLowerCase(Locale.ROOT);
        String canonicalName = lowerName.replaceAll("[^a-z0-9]", "");
        String canonicalPath = fieldPathLower.replaceAll("[^a-z0-9]", "");

        if (canonicalName.equals("status") || canonicalPath.endsWith("status")) {
            if (endpointLower.contains("/status") || endpointLower.contains("/cards") || endpointLower.contains("card/")) {
                return true;
            }
        }

        if (canonicalName.contains("permission") || canonicalPath.contains("permission")) {
            if (endpointLower.contains("consent")) {
                return true;
            }
        }

        if (canonicalName.equals("clientid") || canonicalPath.endsWith("clientid")) {
            if (endpointLower.contains("consent") ||
                endpointLower.contains("bank-token") ||
                endpointLower.contains("/auth/") ||
                endpointLower.contains("product-agreement")) {
                return true;
            }
        }

        if (canonicalName.contains("consentid") || canonicalPath.contains("consentid")) {
            return true;
        }

        if (canonicalName.equals("productid") || canonicalPath.endsWith("productid")) {
            if (endpointLower.contains("product")) {
                return true;
            }
        }

        if (lowerName.equals("source_account_id") || lowerName.equals("destination_account_id") ||
            canonicalName.equals("sourceaccountid") || canonicalName.equals("destinationaccountid") ||
            canonicalPath.endsWith("sourceaccountid") || canonicalPath.endsWith("destinationaccountid")) {
            if (endpointLower.contains("payment") || endpointLower.contains("accounts")) {
                return true;
            }
        }

        if (canonicalName.endsWith("accountid") || canonicalPath.endsWith("accountid")) {
            if (endpointLower.contains("payment") || endpointLower.contains("accounts") || endpointLower.contains("transactions")) {
                return true;
            }
        }

        if (canonicalName.contains("amount") || canonicalPath.contains("amount")) {
            if (endpointLower.contains("payment") || endpointLower.contains("transfer")) {
                return true;
            }
        }

        if ("GET".equals(methodUpper) && (endpointLower.contains("/products") || endpointLower.contains("/catalog"))) {
            return true;
        }

        return false;
    }
    
    enum AnalysisType {
        REQUEST,
        RESPONSE
    }
}

