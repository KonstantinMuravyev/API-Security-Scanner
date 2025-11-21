package com.vtb.scanner.integration;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * INTEGRATION тесты - проверяют ПОЛНЫЙ scan со всеми 11 сканерами!
 * 
 * Это E2E тесты которые проверяют:
 * - Все сканеры работают вместе
 * - Нет конфликтов между сканерами
 * - Корреляция работает
 * - Контекст определяется правильно
 * - Находятся КОНКРЕТНЫЕ уязвимости
 */
class FullScanIntegrationTest {
    
    /**
     * E2E: Полный scan на банковском API
     * 
     * СТРОГАЯ ПРОВЕРКА:
     * - Должно быть >= 15 уязвимостей
     * - Должны быть CRITICAL уязвимости
     * - Должны быть BOLA цепочки
     * - Context должен быть BANKING
     */
    @Test
    void testFullScan_VulnerableBankAPI() {
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.parseFromFile("examples/vulnerable-bank-api.yaml");
        
        com.vtb.scanner.core.SecurityScanner scanner = new com.vtb.scanner.core.SecurityScanner(parser, "http://test.bank", true);
        com.vtb.scanner.models.ScanResult result = scanner.scan();
        
        // 1. ПРОВЕРКА КОЛИЧЕСТВА (строго!)
        assertNotNull(result);
        assertNotNull(result.getVulnerabilities());
        assertTrue(result.getVulnerabilities().size() >= 15,
            String.format("Должно быть >= 15 уязвимостей, найдено: %d", 
                result.getVulnerabilities().size()));
        
        // 2. ПРОВЕРКА SEVERITY
        long criticalCount = result.getVulnerabilities().stream()
            .filter(v -> v.getSeverity() == com.vtb.scanner.models.Severity.CRITICAL)
            .count();
        assertTrue(criticalCount >= 3,
            String.format("Должно быть >= 3 CRITICAL, найдено: %d", criticalCount));
        
        long highCount = result.getVulnerabilities().stream()
            .filter(v -> v.getSeverity() == com.vtb.scanner.models.Severity.HIGH)
            .count();
        assertTrue(highCount >= 5,
            String.format("Должно быть >= 5 HIGH, найдено: %d", highCount));
        
        // 3. ПРОВЕРКА ТИПОВ УЯЗВИМОСТЕЙ
        java.util.List<com.vtb.scanner.models.Vulnerability> vulns = result.getVulnerabilities();
        
        boolean hasBOLA = vulns.stream()
            .anyMatch(v -> v.getType() == com.vtb.scanner.models.VulnerabilityType.BOLA);
        assertTrue(hasBOLA, "Должна быть найдена BOLA!");
        
        boolean hasAuth = vulns.stream()
            .anyMatch(v -> v.getType() == com.vtb.scanner.models.VulnerabilityType.BROKEN_AUTHENTICATION);
        assertTrue(hasAuth, "Должна быть найдена Broken Authentication!");
        
        // 4. ПРОВЕРКА CONFIDENCE (должны быть высокие)
        long highConfidence = vulns.stream()
            .filter(v -> v.getConfidence() >= 70)
            .count();
        assertTrue(highConfidence >= 5,
            String.format("Должно быть >= 5 уязвимостей с confidence >= 70, найдено: %d", 
                highConfidence));
        
        // 5. ПРОВЕРКА PRIORITY
        long priority1 = vulns.stream()
            .filter(v -> v.getPriority() == 1)
            .count();
        assertTrue(priority1 >= 2,
            String.format("Должно быть >= 2 уязвимости с priority=1, найдено: %d", 
                priority1));
        
        // 6. ПРОВЕРКА CONTEXT
        assertEquals("BANKING", result.getApiContext(),
            "Context должен быть BANKING для банковского API");
        
        // 7. ПРОВЕРКА API HEALTH SCORE
        assertTrue(result.getApiHealthScore() < 70,
            String.format("API health score должен быть < 70 для уязвимого API, найдено: %d", 
                result.getApiHealthScore()));
    }
    
    /**
     * E2E: Scan на ГОСТ банковском API
     * 
     * Должны найти ГОСТ нарушения!
     */
    @Test
    void testFullScan_GOSTBankingAPI() {
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.parseFromFile("examples/gost-banking-api.yaml");
        
        com.vtb.scanner.core.SecurityScanner scanner = new com.vtb.scanner.core.SecurityScanner(parser, "http://gost-test.ru", true);
        com.vtb.scanner.models.ScanResult result = scanner.scan();
        
        // ГОСТ нарушения ДОЛЖНЫ быть!
        result.getVulnerabilities().forEach(v ->
            System.out.println("VULN: " + v.getId() + " type=" + v.getType() + " gost=" + v.isGostRelated() + " severity=" + v.getSeverity()));
        long gostViolations = result.getVulnerabilities().stream()
            .filter(com.vtb.scanner.models.Vulnerability::isGostRelated)
            .count();
        
        assertTrue(gostViolations >= 1,
            String.format("Должны быть ГОСТ нарушения, найдено: %d", gostViolations));
    }
    
    /**
     * E2E: Healthcare API
     * 
     * Должны найти ФЗ-152 нарушения!
     */
    @Test
    void testFullScan_HealthcareAPI() {
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.parseFromFile("examples/api-07-healthcare.yaml");
        
        com.vtb.scanner.core.SecurityScanner scanner = new com.vtb.scanner.core.SecurityScanner(parser, "http://health.test", false);
        com.vtb.scanner.models.ScanResult result = scanner.scan();
        
        // Context должен быть HEALTHCARE
        assertEquals("HEALTHCARE", result.getApiContext(),
            "Context должен быть HEALTHCARE");
        
        // Должны быть найдены PII данные
        boolean hasPII = result.getVulnerabilities().stream()
            .anyMatch(v -> v.getDescription() != null && 
                v.getDescription().contains("персональные данные"));
        assertTrue(hasPII, "Должны быть найдены персональные данные");
    }
    
    /**
     * E2E: Government API
     * 
     * Должны требовать ГОСТ!
     */
    @Test
    void testFullScan_GovernmentAPI() {
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.parseFromFile("examples/api-08-government.yaml");
        
        com.vtb.scanner.core.SecurityScanner scanner = new com.vtb.scanner.core.SecurityScanner(parser, "http://gov.test", true);
        com.vtb.scanner.models.ScanResult result = scanner.scan();
        
        assertEquals("GOVERNMENT", result.getApiContext(),
            "Context должен быть GOVERNMENT");
    }
    
    /**
     * E2E: IoT API
     * 
     * Должны найти IoT специфичные уязвимости!
     */
    @Test
    void testFullScan_IoTAPI() {
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.parseFromFile("examples/api-10-iot.yaml");
        
        com.vtb.scanner.core.SecurityScanner scanner = new com.vtb.scanner.core.SecurityScanner(parser, "http://iot.test", false);
        com.vtb.scanner.models.ScanResult result = scanner.scan();
        
        assertEquals("IOT", result.getApiContext(),
            "Context должен быть IOT");
        
        // Должны быть IoT уязвимости
        boolean hasIoT = result.getVulnerabilities().stream()
            .anyMatch(v -> v.getTitle() != null && 
                (v.getTitle().contains("IoT") || v.getTitle().contains("device")));
        assertTrue(hasIoT, "Должны быть найдены IoT уязвимости");
    }
    
    /**
     * PERFORMANCE: Проверка скорости на большом API
     */
    @Test
    void testPerformance_LargeAPI() {
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.parseFromFile("examples/petstore3-real.json"); // Большой API
        
        com.vtb.scanner.core.SecurityScanner scanner = new com.vtb.scanner.core.SecurityScanner(parser, "http://test.com", false);
        
        long start = System.currentTimeMillis();
        com.vtb.scanner.models.ScanResult result = scanner.scan();
        long duration = System.currentTimeMillis() - start;
        
        // Должно быть быстро (< 10 сек для среднего API)
        assertTrue(duration < 10000,
            String.format("Сканирование слишком медленное: %d ms", duration));
        
        System.out.println("⏱️ Performance: " + duration + " ms для " + 
            result.getVulnerabilities().size() + " уязвимостей");
    }
    
    /**
     * CORRELATION: Проверка что находятся BOLA цепочки
     */
    @Test
    void testBOLAChains_Detection() {
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.parseFromFile("examples/vulnerable-bank-api.yaml");
        
        com.vtb.scanner.core.SecurityScanner scanner = new com.vtb.scanner.core.SecurityScanner(parser, "http://test.com", false);
        com.vtb.scanner.models.ScanResult result = scanner.scan();
        
        // Должны быть BOLA цепочки
        boolean hasBOLAChain = result.getVulnerabilities().stream()
            .anyMatch(v -> v.getType() == com.vtb.scanner.models.VulnerabilityType.BOLA && 
                v.getTitle() != null && v.getTitle().contains("цепочка"));
        
        assertTrue(hasBOLAChain, "Должна быть найдена хотя бы 1 BOLA цепочка!");
    }
    
    /**
     * NO DUPLICATES: Проверка что нет дубликатов уязвимостей
     */
    @Test
    void testNoDuplicateVulnerabilities() {
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.parseFromFile("examples/vulnerable-bank-api.yaml");
        
        com.vtb.scanner.core.SecurityScanner scanner = new com.vtb.scanner.core.SecurityScanner(parser, "http://test.com", false);
        com.vtb.scanner.models.ScanResult result = scanner.scan();
        
        java.util.List<com.vtb.scanner.models.Vulnerability> vulns = result.getVulnerabilities();
        
        // Проверяем уникальность ID
        long uniqueIds = vulns.stream()
            .map(com.vtb.scanner.models.Vulnerability::getId)
            .distinct()
            .count();
        
        assertEquals(vulns.size(), uniqueIds,
            String.format("Есть дубликаты! Всего: %d, уникальных ID: %d", 
                vulns.size(), uniqueIds));
    }
}

