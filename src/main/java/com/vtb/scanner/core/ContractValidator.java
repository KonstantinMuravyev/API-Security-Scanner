package com.vtb.scanner.core;

import com.vtb.scanner.models.ContractViolation;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.ViolationType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Валидатор контракта API
 * Проверяет соответствие реального поведения API его спецификации
 */
@Slf4j
public class ContractValidator {
    
    private final OpenAPIParser parser;
    private final String targetUrl;
    private final OkHttpClient httpClient;
    
    public ContractValidator(OpenAPIParser parser, String targetUrl) {
        this.parser = parser;
        this.targetUrl = targetUrl;
        this.httpClient = new OkHttpClient.Builder()
            .followRedirects(false)
            .build();
    }
    
    /**
     * Валидация контракта для всех эндпоинтов
     */
    public List<ContractViolation> validate() {
        log.info("Начало валидации контракта API");
        
        List<ContractViolation> violations = new ArrayList<>();
        
        // КРИТИЧНО: Проверка на null
        if (parser == null) {
            log.error("Parser не инициализирован");
            return violations;
        }
        
        OpenAPI openAPI = parser.getOpenAPI();
        if (openAPI == null) {
            log.error("OpenAPI спецификация не загружена");
            return violations;
        }
        
        // КРИТИЧНО: Проверка targetUrl
        if (targetUrl == null || targetUrl.trim().isEmpty()) {
            log.warn("Target URL не указан, пропускаем HTTP валидацию");
            return violations;
        }
        
        if (openAPI.getPaths() == null) {
            log.warn("Нет эндпоинтов для валидации");
            return violations;
        }
        
        // Проверяем каждый эндпоинт
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            violations.addAll(validatePath(path, pathItem));
        }
        
        log.info("Найдено нарушений контракта: {}", violations.size());
        return violations;
    }
    
    /**
     * Валидация конкретного пути
     */
    private List<ContractViolation> validatePath(String path, PathItem pathItem) {
        List<ContractViolation> violations = new ArrayList<>();
        
        // Проверяем GET
        if (pathItem.getGet() != null) {
            violations.addAll(validateOperation(path, "GET", pathItem.getGet()));
        }
        
        // Проверяем POST
        if (pathItem.getPost() != null) {
            violations.addAll(validateOperation(path, "POST", pathItem.getPost()));
        }
        
        // Проверяем PUT
        if (pathItem.getPut() != null) {
            violations.addAll(validateOperation(path, "PUT", pathItem.getPut()));
        }
        
        // Проверяем DELETE
        if (pathItem.getDelete() != null) {
            violations.addAll(validateOperation(path, "DELETE", pathItem.getDelete()));
        }
        
        return violations;
    }
    
    /**
     * Валидация конкретной операции
     */
    private List<ContractViolation> validateOperation(String path, String method, Operation operation) {
        List<ContractViolation> violations = new ArrayList<>();
        
        // Проверка наличия responses
        if (operation.getResponses() == null || operation.getResponses().isEmpty()) {
            violations.add(ContractViolation.builder()
                .endpoint(path)
                .method(method)
                .type(ViolationType.SCHEMA_MISMATCH)
                .description("Отсутствует описание ответов в спецификации")
                .severity(Severity.MEDIUM)
                .build());
        }
        
        // Проверка Security
        if (operation.getSecurity() == null || operation.getSecurity().isEmpty()) {
            // Проверяем глобальную security
            OpenAPI openAPI = parser.getOpenAPI();
            if (openAPI.getSecurity() == null || openAPI.getSecurity().isEmpty()) {
                violations.add(ContractViolation.builder()
                    .endpoint(path)
                    .method(method)
                    .type(ViolationType.MISSING_HEADER)
                    .description("Эндпоинт не защищен аутентификацией")
                    .expected("Security scheme")
                    .actual("None")
                    .severity(Severity.HIGH)
                    .build());
            }
        }
        
        // Дополнительные проверки можно добавить здесь
        
        return violations;
    }
    
    /**
     * Выполнить HTTP запрос для проверки
     */
    private Response executeRequest(String path, String method) throws IOException {
        // КРИТИЧНО: Защита от null
        if (targetUrl == null || targetUrl.trim().isEmpty()) {
            throw new IllegalStateException("Target URL не указан");
        }
        
        if (path == null) {
            path = "";
        }
        
        String fullUrl = targetUrl + path;
        
        // КРИТИЧНО: Валидация URL перед запросом
        if (!fullUrl.startsWith("http://") && !fullUrl.startsWith("https://")) {
            throw new IllegalArgumentException("Неверный формат URL: " + fullUrl);
        }
        
        Request.Builder requestBuilder = new Request.Builder()
            .url(fullUrl)
            .method(method, method.equals("GET") ? null : RequestBody.create("", MediaType.get("application/json")));
        
        Request request = requestBuilder.build();
        return httpClient.newCall(request).execute();
    }
}

