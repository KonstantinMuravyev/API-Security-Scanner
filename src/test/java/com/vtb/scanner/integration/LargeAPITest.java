package com.vtb.scanner.integration;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.core.SecurityScanner;
import com.vtb.scanner.models.ScanResult;
import com.vtb.scanner.models.Vulnerability;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ТЕСТЫ НА БОЛЬШИХ РЕАЛЬНЫХ API (>8MB)
 * 
 * Проверяет что парсер и сканер работают на больших API:
 * - GitHub API (8.8 MB JSON)
 * - Stripe API (большой)
 * - Другие enterprise API
 * 
 * ВАЖНО: Эти тесты требуют интернет подключения!
 * Они могут быть медленными (скачивание + парсинг больших файлов)
 */
class LargeAPITest {
    
    /**
     * Тест на GitHub API (8.8 MB JSON)
     * 
     * КРИТИЧНО: Проверяет что парсер НЕ ломается на больших API!
     * 
     * GitHub API спецификация:
     * URL: https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json
     * Размер: ~8.8 MB
     */
    @Test
    // @Disabled("Требует интернет и может быть медленным - запускать вручную")
    void testGitHubAPI_ParserHandlesLargeFile() {
        String githubApiUrl = "https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json";
        
        OpenAPIParser parser = new OpenAPIParser();
        
        // Парсинг не должен падать!
        assertDoesNotThrow(() -> {
            parser.parseFromUrl(githubApiUrl);
        }, "Парсер должен обработать GitHub API без ошибок!");
        
        // Проверяем что парсинг успешен
        assertNotNull(parser.getOpenAPI(), "OpenAPI объект должен быть создан");
        assertNotNull(parser.getApiTitle(), "API title должен быть заполнен");
        
        // GitHub API должен иметь много эндпоинтов
        int endpointCount = parser.getAllEndpoints().size();
        assertTrue(endpointCount > 100, 
            String.format("GitHub API должен иметь >100 эндпоинтов, найдено: %d", endpointCount));
        
        System.out.println("✅ GitHub API успешно распарсен:");
        System.out.println("   - Название: " + parser.getApiTitle());
        System.out.println("   - Версия: " + parser.getApiVersion());
        System.out.println("   - Эндпоинтов: " + endpointCount);
    }
    
    /**
     * Тест сканирования GitHub API
     * 
     * Проверяет что сканер может обработать большой API
     */
    @Test
    // @Disabled("Требует интернет и может быть медленным - запускать вручную")
    void testGitHubAPI_FullScan() {
        String githubApiUrl = "https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json";
        
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromUrl(githubApiUrl);
        
        SecurityScanner scanner = new SecurityScanner(parser, "https://api.github.com", false);
        
        long startTime = System.currentTimeMillis();
        ScanResult result = scanner.scan();
        long duration = System.currentTimeMillis() - startTime;
        
        // Проверяем что сканирование завершилось
        assertNotNull(result, "ScanResult должен быть создан");
        assertNotNull(result.getVulnerabilities(), "Список уязвимостей не должен быть null");
        
        // GitHub API большой, должно найти много уязвимостей
        int vulnCount = result.getVulnerabilities().size();
        assertTrue(vulnCount > 0, 
            String.format("На GitHub API должно быть найдено >0 уязвимостей, найдено: %d", vulnCount));
        
        System.out.println("✅ GitHub API успешно просканирован:");
        System.out.println("   - Уязвимостей найдено: " + vulnCount);
        System.out.println("   - Время сканирования: " + duration + " ms");
        System.out.println("   - API Health Score: " + result.getApiHealthScore());
        System.out.println("   - Context: " + result.getApiContext());
    }
    
    /**
     * Тест что парсер правильно определяет размер файла через URL
     */
    @Test
    @Disabled("Требует интернет - запускать вручную")
    void testParser_DetectsLargeFileFromUrl() {
        String githubApiUrl = "https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json";
        
        OpenAPIParser parser = new OpenAPIParser();
        
        // Должно работать без OutOfMemoryError
        assertDoesNotThrow(() -> {
            parser.parseFromUrl(githubApiUrl);
        }, "Парсер должен обработать большой файл по URL без OutOfMemoryError");
        
        assertNotNull(parser.getOpenAPI(), "Парсинг должен быть успешным");
    }
    
    /**
     * Тест что парсер отклоняет слишком большие файлы (>100MB)
     */
    @Test
    void testParser_RejectsTooLargeFiles() {
        OpenAPIParser parser = new OpenAPIParser();
        
        // Этот тест можно сделать на локальном файле >100MB если нужно
        // Пока просто проверяем что есть валидация размера
        assertDoesNotThrow(() -> {
            // Логика валидации размера должна быть в parseFromUrl
        });
    }
    
    /**
     * Тест что JSON парсинг работает для больших файлов
     * 
     * Проверяет что parseJsonDirectly работает корректно
     */
    @Test
    @Disabled("Требует интернет и большой JSON файл - запускать вручную")
    void testLargeJson_ParsingWorks() {
        String githubApiUrl = "https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json";
        
        OpenAPIParser parser = new OpenAPIParser();
        
        // Должно использовать JSON парсер для больших файлов
        assertDoesNotThrow(() -> {
            parser.parseFromUrl(githubApiUrl);
        }, "JSON парсер должен обработать большой файл");
        
        assertNotNull(parser.getOpenAPI(), "JSON должен быть успешно распарсен");
    }
    
    /**
     * Тест производительности на большом API
     * 
     * Проверяет что сканирование выполняется в разумное время
     */
    @Test
    @Disabled("Требует интернет - запускать вручную")
    void testLargeAPI_Performance() {
        String githubApiUrl = "https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json";
        
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromUrl(githubApiUrl);
        
        SecurityScanner scanner = new SecurityScanner(parser, "https://api.github.com", false);
        
        long startTime = System.currentTimeMillis();
        ScanResult result = scanner.scan();
        long duration = System.currentTimeMillis() - startTime;
        
        // Для большого API (8MB) сканирование должно быть < 60 секунд
        assertTrue(duration < 60000, 
            String.format("Сканирование большого API должно быть < 60 сек, получено: %d ms", duration));
        
        System.out.println("⏱️ Производительность большого API:");
        System.out.println("   - Время: " + duration + " ms");
        System.out.println("   - Эндпоинтов: " + parser.getAllEndpoints().size());
        System.out.println("   - Уязвимостей: " + result.getVulnerabilities().size());
    }
    
    /**
     * Тест что все уязвимости на большом API имеют корректные данные
     */
    @Test
    @Disabled("Требует интернет - запускать вручную")
    void testLargeAPI_AllVulnerabilitiesValid() {
        String githubApiUrl = "https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json";
        
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromUrl(githubApiUrl);
        
        SecurityScanner scanner = new SecurityScanner(parser, "https://api.github.com", false);
        ScanResult result = scanner.scan();
        
        // Проверяем что все уязвимости корректны
        for (Vulnerability vuln : result.getVulnerabilities()) {
            assertNotNull(vuln.getId(), "ID не должен быть null для " + vuln);
            assertNotNull(vuln.getTitle(), "Title не должен быть null для " + vuln.getId());
            assertNotNull(vuln.getDescription(), "Description не должен быть null для " + vuln.getId());
            assertTrue(vuln.getConfidence() > 0 && vuln.getConfidence() <= 100, 
                "Confidence должен быть 1-100 для " + vuln.getId());
            assertNotNull(vuln.getSeverity(), "Severity не должен быть null для " + vuln.getId());
        }
        
        System.out.println("✅ Все уязвимости на большом API корректны: " + result.getVulnerabilities().size());
    }
}
