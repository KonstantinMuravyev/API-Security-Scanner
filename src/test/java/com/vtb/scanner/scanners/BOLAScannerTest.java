package com.vtb.scanner.scanners;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import io.swagger.v3.oas.models.OpenAPI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты для BOLAScanner
 */
class BOLAScannerTest {
    
    private OpenAPIParser parser;
    private BOLAScanner scanner;
    
    @BeforeEach
    void setUp() {
        parser = new OpenAPIParser();
        parser.parseFromFile("examples/vulnerable-bank-api.yaml");
        scanner = new BOLAScanner("http://test.com");
    }
    
    @Test
    void testFindsBOLAVulnerabilities() {
        OpenAPI openAPI = parser.getOpenAPI();
        List<Vulnerability> vulnerabilities = scanner.scan(openAPI, parser);
        
        assertNotNull(vulnerabilities);
        assertTrue(vulnerabilities.size() > 0, "Должны быть найдены BOLA уязвимости");
        
        // Проверяем что найдены критичные уязвимости
        long criticalCount = vulnerabilities.stream()
            .filter(v -> v.getSeverity() == Severity.CRITICAL)
            .count();
        
        assertTrue(criticalCount > 0, "Должны быть CRITICAL уязвимости");
    }
    
    @Test
    void testDetectsIdParameters() {
        OpenAPI openAPI = parser.getOpenAPI();
        List<Vulnerability> vulnerabilities = scanner.scan(openAPI, parser);
        
        // Проверяем что найдены эндпоинты с ID
        boolean foundAccountId = vulnerabilities.stream()
            .anyMatch(v -> v.getEndpoint().contains("accountId"));
        
        assertTrue(foundAccountId, "Должен быть найден /accounts/{accountId}");
    }
    
    @Test
    void testCorrectOWASPCategory() {
        OpenAPI openAPI = parser.getOpenAPI();
        List<Vulnerability> vulnerabilities = scanner.scan(openAPI, parser);
        
        for (Vulnerability vuln : vulnerabilities) {
            // BOLA может быть "API1:2023" или содержать "Broken Object Level Authorization"
            assertTrue(
                vuln.getOwaspCategory().contains("API1:2023") ||
                vuln.getOwaspCategory().toLowerCase().contains("bola") ||
                vuln.getOwaspCategory().toLowerCase().contains("broken object"),
                "OWASP категория должна быть API1:2023 или содержать BOLA/Broken Object, но была: " + vuln.getOwaspCategory()
            );
        }
    }
}

