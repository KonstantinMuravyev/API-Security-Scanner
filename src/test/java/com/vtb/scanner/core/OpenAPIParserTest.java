package com.vtb.scanner.core;

import io.swagger.v3.oas.models.OpenAPI;
import org.junit.jupiter.api.Test;

import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты для OpenAPIParser
 */
class OpenAPIParserTest {
    
    @Test
    void testParseValidYaml() {
        OpenAPIParser parser = new OpenAPIParser();
        
        // Используем тестовый файл
        String testFile = "examples/petstore-api.yaml";
        parser.parseFromFile(testFile);
        
        OpenAPI openAPI = parser.getOpenAPI();
        assertNotNull(openAPI, "OpenAPI объект должен быть создан");
        assertEquals("Pet Store API (Тестовый пример)", parser.getApiTitle());
        assertEquals("1.0.0", parser.getApiVersion());
        assertNotNull(parser.getAllEndpoints(), "Эндпоинты должны быть загружены");
        assertTrue(parser.getAllEndpoints().size() > 0, "Должны быть эндпоинты");
    }
    
    @Test
    void testGetServerUrl() {
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromFile("examples/petstore-api.yaml");
        
        String serverUrl = parser.getServerUrl();
        assertNotNull(serverUrl, "Server URL должен быть определен");
        assertTrue(serverUrl.startsWith("http"), "Server URL должен начинаться с http");
    }
    
    @Test
    void testParseInvalidFile() {
        OpenAPIParser parser = new OpenAPIParser();
        
        assertThrows(IllegalArgumentException.class, () -> {
            parser.parseFromFile("nonexistent.yaml");
        }, "Должна быть ошибка при несуществующем файле");
    }
}

