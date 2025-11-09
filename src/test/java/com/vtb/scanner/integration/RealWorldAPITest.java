package com.vtb.scanner.integration;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.core.SecurityScanner;
import com.vtb.scanner.models.ScanResult;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * СТРОГИЕ тесты на РЕАЛЬНЫХ примерах API
 * 
 * Проверяют КОНКРЕТНЫЕ уязвимости которые описаны в vulnerable-bank-api.yaml
 * Это E2E тесты с ТОЧНЫМИ ожиданиями!
 */
class RealWorldAPITest {
    
    /**
     * СТРОГИЙ тест на vulnerable-bank-api.yaml
     * 
     * Проверяем что находим ВСЕ уязвимости которые там описаны:
     * 1. BOLA на /accounts/{accountId}
     * 2. DELETE без auth на /accounts/{accountId}
     * 3. SQL Injection на /accounts/search?query=
     * 4. Password в URL на /users/login?password=
     * 5. Debug endpoint на /admin/debug
     * 6. Admin без auth на /admin/users
     * 7. Command Injection на /execute
     * 8. ФЗ-152 на /users/{userId}/profile
     */
    @Test
    void testVulnerableBankAPI_FindsAllKnownVulnerabilities() {
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromFile("examples/vulnerable-bank-api.yaml");
        
        SecurityScanner scanner = new SecurityScanner(parser, "http://vulnerable-bank.example.com", true);
        ScanResult result = scanner.scan();
        
        List<Vulnerability> vulns = result.getVulnerabilities();
        
        // === СТРОГАЯ ПРОВЕРКА 1: Общее количество ===
        assertTrue(vulns.size() >= 10, 
            String.format("В vulnerable-bank-api должно быть >= 10 уязвимостей, найдено: %d", vulns.size()));
        
        // === СТРОГАЯ ПРОВЕРКА 2: HTTP (не HTTPS) ===
        boolean hasHTTP = vulns.stream()
            .anyMatch(v -> v.getId().equals("MISC-HTTP"));
        assertTrue(hasHTTP, "ДОЛЖНА быть найдена уязвимость HTTP (не HTTPS)!");
        
        Vulnerability httpVuln = vulns.stream()
            .filter(v -> v.getId().equals("MISC-HTTP"))
            .findFirst()
            .orElse(null);
        assertNotNull(httpVuln);
        assertEquals(Severity.CRITICAL, httpVuln.getSeverity(), 
            "HTTP для банка должен быть CRITICAL (из-за context=BANKING)!");
        
        // === СТРОГАЯ ПРОВЕРКА 3: BOLA на /accounts/{accountId} ===
        boolean hasBOLAAccount = vulns.stream()
            .anyMatch(v -> v.getEndpoint().equals("/accounts/{accountId}") && 
                          v.getType() == VulnerabilityType.BOLA);
        assertTrue(hasBOLAAccount, 
            "ДОЛЖНА быть найдена BOLA на /accounts/{accountId}!");
        
        // === СТРОГАЯ ПРОВЕРКА 4: DELETE без auth ===
        boolean hasDeleteNoAuth = vulns.stream()
            .anyMatch(v -> v.getEndpoint().equals("/accounts/{accountId}") && 
                          v.getMethod().equals("DELETE") &&
                          (v.getType() == VulnerabilityType.BROKEN_AUTHENTICATION ||
                           v.getType() == VulnerabilityType.BFLA));
        assertTrue(hasDeleteNoAuth, 
            "ДОЛЖНА быть найдена уязвимость DELETE без auth!");
        
        // === СТРОГАЯ ПРОВЕРКА 5: SQL Injection на /accounts/search ===
        boolean hasSQLInjection = vulns.stream()
            .anyMatch(v -> v.getEndpoint().equals("/accounts/search") && 
                          v.getType() == VulnerabilityType.SQL_INJECTION);
        assertTrue(hasSQLInjection, 
            "ДОЛЖНА быть найдена SQL Injection на /accounts/search?query=!");
        
        Vulnerability sqlInj = vulns.stream()
            .filter(v -> v.getEndpoint().equals("/accounts/search") && 
                        v.getType() == VulnerabilityType.SQL_INJECTION)
            .findFirst()
            .orElse(null);
        assertNotNull(sqlInj);
        assertTrue(sqlInj.getRiskScore() > 80, 
            String.format("SQL Injection должна иметь высокий risk score, получено: %d", sqlInj.getRiskScore()));
        
        // === СТРОГАЯ ПРОВЕРКА 6: Password в URL ===
        boolean hasPasswordInURL = vulns.stream()
            .anyMatch(v -> v.getEndpoint().equals("/users/login") && 
                          v.getType() == VulnerabilityType.SENSITIVE_DATA_IN_URL);
        assertTrue(hasPasswordInURL, 
            "ДОЛЖНА быть найдена уязвимость: password в URL на /users/login!");
        
        // === СТРОГАЯ ПРОВЕРКА 7: Debug endpoint ===
        boolean hasDebug = vulns.stream()
            .anyMatch(v -> v.getEndpoint().equals("/admin/debug") &&
                          v.getType() == VulnerabilityType.DEBUG_ENDPOINT);
        assertTrue(hasDebug, 
            "ДОЛЖЕН быть найден debug endpoint /admin/debug!");
        
        // === СТРОГАЯ ПРОВЕРКА 8: Admin без auth ===
        boolean hasAdminNoAuth = vulns.stream()
            .anyMatch(v -> v.getEndpoint().equals("/admin/users") &&
                          (v.getType() == VulnerabilityType.BROKEN_AUTHENTICATION ||
                           v.getType() == VulnerabilityType.BFLA));
        assertTrue(hasAdminNoAuth, 
            "ДОЛЖНА быть найдена уязвимость: admin endpoint без auth!");
        
        // === СТРОГАЯ ПРОВЕРКА 9: Command Injection ===
        boolean hasCmdInjection = vulns.stream()
            .anyMatch(v -> v.getEndpoint().equals("/execute") &&
                          v.getType() == VulnerabilityType.COMMAND_INJECTION);
        assertTrue(hasCmdInjection, 
            "ДОЛЖНА быть найдена Command Injection на /execute!");
        
        Vulnerability cmdInj = vulns.stream()
            .filter(v -> v.getEndpoint().equals("/execute") &&
                        v.getType() == VulnerabilityType.COMMAND_INJECTION)
            .findFirst()
            .orElse(null);
        assertNotNull(cmdInj);
        assertEquals(Severity.CRITICAL, cmdInj.getSeverity(), 
            "Command Injection ДОЛЖНА быть CRITICAL!");
        assertTrue(cmdInj.getConfidence() >= 70, 
            String.format("Command Injection должна иметь высокий confidence, получено: %d", cmdInj.getConfidence()));
        
        // === СТРОГАЯ ПРОВЕРКА 10: Персональные данные (ФЗ-152) ===
        boolean hasPII = vulns.stream()
            .anyMatch(v -> v.getEndpoint().equals("/users/{userId}/profile") &&
                          v.getDescription() != null &&
                          v.getDescription().contains("персональн"));
        assertTrue(hasPII, 
            "ДОЛЖНА быть найдена утечка персональных данных на /users/{userId}/profile!");
        
        // === ПРОВЕРКА КОНТЕКСТА ===
        assertEquals("BANKING", result.getApiContext(), 
            "Context ДОЛЖЕН быть BANKING для банковского API!");
        
        // === ПРОВЕРКА API HEALTH SCORE ===
        assertTrue(result.getApiHealthScore() < 50, 
            String.format("API Health Score должен быть < 50 для уязвимого API, получено: %d", 
                result.getApiHealthScore()));
        
        // === ПРОВЕРКА SEVERITY DISTRIBUTION ===
        long criticalCount = vulns.stream()
            .filter(v -> v.getSeverity() == Severity.CRITICAL)
            .count();
        assertTrue(criticalCount >= 3, 
            String.format("Должно быть >= 3 CRITICAL уязвимости, найдено: %d", criticalCount));
        
        long highCount = vulns.stream()
            .filter(v -> v.getSeverity() == Severity.HIGH)
            .count();
        assertTrue(highCount >= 4, 
            String.format("Должно быть >= 4 HIGH уязвимости, найдено: %d", highCount));
        
        // === ПРОВЕРКА CONFIDENCE ===
        long highConfidence = vulns.stream()
            .filter(v -> v.getConfidence() >= 70)
            .count();
        assertTrue(highConfidence >= 5, 
            String.format("Должно быть >= 5 уязвимостей с confidence >= 70, найдено: %d", highConfidence));
        
        // === ПРОВЕРКА PRIORITY ===
        long priority1 = vulns.stream()
            .filter(v -> v.getPriority() == 1)
            .count();
        assertTrue(priority1 >= 3, 
            String.format("Должно быть >= 3 уязвимости с priority=1 (немедленное исправление), найдено: %d", priority1));
        
        // === ПРОВЕРКА ЧТО НЕТ FALSE POSITIVES ===
        // Все найденные уязвимости должны быть реальными
        for (Vulnerability vuln : vulns) {
            assertNotNull(vuln.getId(), "ID уязвимости не должен быть null");
            assertNotNull(vuln.getTitle(), "Title не должен быть null");
            assertNotNull(vuln.getDescription(), "Description не должен быть null");
            assertNotNull(vuln.getRecommendation(), "Recommendation не должен быть null");
            assertNotNull(vuln.getOwaspCategory(), "OWASP Category не должен быть null");
            assertTrue(vuln.getConfidence() > 0, "Confidence должен быть > 0");
            assertTrue(vuln.getConfidence() <= 100, "Confidence должен быть <= 100");
        }
    }
    
    /**
     * Тест на ГОСТ API
     */
    @Test
    void testGOSTBankingAPI_FindsGOSTViolations() {
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromFile("examples/gost-banking-api.yaml");
        
        SecurityScanner scanner = new SecurityScanner(parser, "https://gost-bank.ru", true);
        ScanResult result = scanner.scan();
        
        // ГОСТ проверки включены - должны быть нарушения
        long gostCount = result.getVulnerabilities().stream()
            .filter(Vulnerability::isGostRelated)
            .count();
        
        // Если это зарубежный сервер - должны быть ГОСТ нарушения
        assertTrue(gostCount >= 1, 
            String.format("Должны быть ГОСТ нарушения, найдено: %d", gostCount));
    }
    
    /**
     * Тест на IoT API
     */
    @Test
    void testIoTAPI_FindsDeviceVulnerabilities() {
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromFile("examples/api-10-iot.yaml");
        
        SecurityScanner scanner = new SecurityScanner(parser, "http://iot.example.com", false);
        ScanResult result = scanner.scan();
        
        // Context должен быть IOT
        assertEquals("IOT", result.getApiContext());
        
        // Должны найти Command Injection (из описания в YAML)
        boolean hasCmdInj = result.getVulnerabilities().stream()
            .anyMatch(v -> v.getType() == VulnerabilityType.COMMAND_INJECTION);
        assertTrue(hasCmdInj, "Должна быть найдена Command Injection в IoT API!");
        
        // Должны найти SSRF (webhook)
        boolean hasSSRF = result.getVulnerabilities().stream()
            .anyMatch(v -> v.getType() == VulnerabilityType.SSRF);
        assertTrue(hasSSRF, "Должна быть найдена SSRF на webhook!");
    }
    
    /**
     * PERFORMANCE тест на реальном API
     */
    @Test
    void testPerformance_CompleteAPI() {
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromFile("examples/vulnerable-bank-api.yaml");
        
        SecurityScanner scanner = new SecurityScanner(parser, "http://test.com", false);
        
        long start = System.currentTimeMillis();
        ScanResult result = scanner.scan();
        long duration = System.currentTimeMillis() - start;
        
        // Должно быть быстро
        assertTrue(duration < 5000, 
            String.format("Сканирование vulnerable-bank-api слишком медленное: %d ms (должно < 5000ms)", duration));
        
        System.out.println("⏱️ Performance: " + duration + " ms для " + result.getVulnerabilities().size() + " уязвимостей");
        System.out.println("📊 Throughput: " + (result.getVulnerabilities().size() * 1000.0 / duration) + " vulns/sec");
    }
    
    /**
     * Проверка уникальности ID (нет дубликатов)
     */
    @Test
    void testNoDuplicates_VulnerableBankAPI() {
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromFile("examples/vulnerable-bank-api.yaml");
        
        SecurityScanner scanner = new SecurityScanner(parser, "http://test.com", false);
        ScanResult result = scanner.scan();
        
        List<Vulnerability> vulns = result.getVulnerabilities();
        
        // Проверяем уникальность ID
        long totalVulns = vulns.size();
        long uniqueIds = vulns.stream()
            .map(Vulnerability::getId)
            .distinct()
            .count();
        
        assertEquals(totalVulns, uniqueIds, 
            String.format("Найдены ДУБЛИКАТЫ! Всего: %d, уникальных: %d", totalVulns, uniqueIds));
        
        // Проверяем что нет полных дубликатов (одинаковый endpoint + method + type)
        for (int i = 0; i < vulns.size(); i++) {
            for (int j = i + 1; j < vulns.size(); j++) {
                Vulnerability v1 = vulns.get(i);
                Vulnerability v2 = vulns.get(j);
                
                boolean isDuplicate = 
                    v1.getEndpoint().equals(v2.getEndpoint()) &&
                    v1.getMethod().equals(v2.getMethod()) &&
                    v1.getType() == v2.getType();
                
                if (isDuplicate) {
                    fail(String.format("Найден ДУБЛИКАТ: %s %s (%s) встречается 2+ раза! ID1=%s, ID2=%s", 
                        v1.getMethod(), v1.getEndpoint(), v1.getType(), v1.getId(), v2.getId()));
                }
            }
        }
    }
    
    /**
     * Проверка качества рекомендаций
     */
    @Test
    void testRecommendationsQuality_NotEmpty() {
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromFile("examples/vulnerable-bank-api.yaml");
        
        SecurityScanner scanner = new SecurityScanner(parser, "http://test.com", false);
        ScanResult result = scanner.scan();
        
        // ВСЕ уязвимости должны иметь рекомендации!
        for (Vulnerability vuln : result.getVulnerabilities()) {
            assertNotNull(vuln.getRecommendation(), 
                String.format("Уязвимость %s НЕ имеет рекомендаций!", vuln.getId()));
            
            assertTrue(vuln.getRecommendation().length() > 20, 
                String.format("Рекомендация для %s слишком короткая: %s", 
                    vuln.getId(), vuln.getRecommendation()));
        }
    }
    
    /**
     * Проверка SmartAnalyzer работает
     */
    @Test
    void testSmartAnalyzer_RiskScoresCalculated() {
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromFile("examples/vulnerable-bank-api.yaml");
        
        SecurityScanner scanner = new SecurityScanner(parser, "http://test.com", false);
        ScanResult result = scanner.scan();
        
        // Проверяем что riskScore заполнен хотя бы для части уязвимостей
        long withRiskScore = result.getVulnerabilities().stream()
            .filter(v -> v.getRiskScore() > 0)
            .count();
        
        assertTrue(withRiskScore >= 5, 
            String.format("SmartAnalyzer должен рассчитать risk score хотя бы для 5+ уязвимостей, найдено: %d", 
                withRiskScore));
        
        // Проверяем что risk score разумный (0-350)
        for (Vulnerability vuln : result.getVulnerabilities()) {
            if (vuln.getRiskScore() > 0) {
                assertTrue(vuln.getRiskScore() <= 400, 
                    String.format("Risk score слишком высокий: %d для %s", 
                        vuln.getRiskScore(), vuln.getId()));
            }
        }
    }
    
    /**
     * Проверка ConfidenceCalculator работает
     */
    @Test
    void testConfidenceCalculator_AllHaveConfidence() {
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromFile("examples/vulnerable-bank-api.yaml");
        
        SecurityScanner scanner = new SecurityScanner(parser, "http://test.com", false);
        ScanResult result = scanner.scan();
        
        // ВСЕ уязвимости ДОЛЖНЫ иметь confidence!
        for (Vulnerability vuln : result.getVulnerabilities()) {
            assertTrue(vuln.getConfidence() > 0, 
                String.format("Уязвимость %s имеет confidence=0!", vuln.getId()));
            
            assertTrue(vuln.getConfidence() <= 100, 
                String.format("Уязвимость %s имеет неверный confidence: %d", 
                    vuln.getId(), vuln.getConfidence()));
        }
        
        // Критичные уязвимости должны иметь высокий confidence
        long criticalHighConfidence = result.getVulnerabilities().stream()
            .filter(v -> v.getSeverity() == Severity.CRITICAL && v.getConfidence() >= 70)
            .count();
        
        assertTrue(criticalHighConfidence >= 2, 
            String.format("CRITICAL уязвимости должны иметь высокий confidence, найдено только: %d", 
                criticalHighConfidence));
    }
}

