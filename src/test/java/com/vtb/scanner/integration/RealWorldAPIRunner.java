package com.vtb.scanner.integration;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.core.SecurityScanner;
import com.vtb.scanner.models.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * РУЧНОЙ ЗАПУСК ТЕСТОВ НА РЕАЛЬНЫХ API
 * 
 * Этот класс можно запустить напрямую для тестирования на реальных API из интернета
 * 
 * Запуск: java -cp target/classes:target/test-classes com.vtb.scanner.integration.RealWorldAPIRunner
 */
public class RealWorldAPIRunner {
    
    public static void main(String[] args) {
        System.out.println("🚀 ЗАПУСК ТЕСТОВ НА РЕАЛЬНЫХ API\n");
        System.out.println("=" .repeat(80));
        
        // 1. GitHub API (8.8 MB) - КРИТИЧНО!
        testGitHubAPI();
        
        System.out.println("\n" + "=".repeat(80) + "\n");
        
        // 2. Swagger Petstore (стандартный пример)
        testSwaggerPetstore();
        
        System.out.println("\n" + "=".repeat(80) + "\n");
        
        // 3. Stripe API (если доступна спецификация)
        // testStripeAPI();
        
        System.out.println("\n✅ ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ!");
    }
    
    /**
     * Тест на GitHub API (8.8 MB JSON)
     * КРИТИЧНЫЙ ТЕСТ - проверяет что парсер работает на больших API!
     */
    private static void testGitHubAPI() {
        System.out.println("📦 ТЕСТ 1: GitHub API (8.8 MB JSON)");
        System.out.println("-".repeat(80));
        
        String githubApiUrl = "https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json";
        
        try {
            long startTime = System.currentTimeMillis();
            
            // 1. Парсинг
            System.out.println("⏳ Парсинг GitHub API...");
            OpenAPIParser parser = new OpenAPIParser();
            parser.parseFromUrl(githubApiUrl);
            
            long parseTime = System.currentTimeMillis() - startTime;
            
            System.out.println("✅ Парсинг успешен за " + parseTime + " ms");
            System.out.println("   - Название: " + parser.getApiTitle());
            System.out.println("   - Версия: " + parser.getApiVersion());
            System.out.println("   - Эндпоинтов: " + parser.getAllEndpoints().size());
            
            // 2. Сканирование
            System.out.println("\n⏳ Сканирование GitHub API...");
            SecurityScanner scanner = new SecurityScanner(parser, "https://api.github.com", false);
            
            long scanStart = System.currentTimeMillis();
            ScanResult result = scanner.scan();
            long scanTime = System.currentTimeMillis() - scanStart;
            
            // 3. Результаты
            System.out.println("\n📊 РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ:");
            System.out.println("   - Всего уязвимостей: " + result.getVulnerabilities().size());
            System.out.println("   - Время сканирования: " + scanTime + " ms");
            System.out.println("   - API Health Score: " + result.getApiHealthScore());
            System.out.println("   - Context: " + result.getApiContext());
            
            // 4. Детальная статистика
            Map<Severity, Long> bySeverity = result.getVulnerabilities().stream()
                .collect(Collectors.groupingBy(Vulnerability::getSeverity, Collectors.counting()));
            
            System.out.println("\n📈 ПО SEVERITY:");
            for (Severity severity : Severity.values()) {
                long count = bySeverity.getOrDefault(severity, 0L);
                if (count > 0) {
                    System.out.println("   - " + severity + ": " + count);
                }
            }
            
            // 5. По типам уязвимостей
            Map<VulnerabilityType, Long> byType = result.getVulnerabilities().stream()
                .collect(Collectors.groupingBy(Vulnerability::getType, Collectors.counting()));
            
            System.out.println("\n🔍 ТОП-10 ТИПОВ УЯЗВИМОСТЕЙ:");
            byType.entrySet().stream()
                .sorted(Map.Entry.<VulnerabilityType, Long>comparingByValue().reversed())
                .limit(10)
                .forEach(entry -> System.out.println("   - " + entry.getKey() + ": " + entry.getValue()));
            
            // 6. Примеры критичных уязвимостей
            List<Vulnerability> critical = result.getVulnerabilities().stream()
                .filter(v -> v.getSeverity() == Severity.CRITICAL)
                .limit(5)
                .collect(Collectors.toList());
            
            if (!critical.isEmpty()) {
                System.out.println("\n🚨 ПРИМЕРЫ КРИТИЧНЫХ УЯЗВИМОСТЕЙ:");
                for (Vulnerability vuln : critical) {
                    System.out.println("   - [" + vuln.getType() + "] " + vuln.getTitle());
                    System.out.println("     Endpoint: " + vuln.getEndpoint() + " " + vuln.getMethod());
                    System.out.println("     Confidence: " + vuln.getConfidence() + "%");
                }
            }
            
            // 7. Валидация
            System.out.println("\n✅ ВАЛИДАЦИЯ РЕЗУЛЬТАТОВ:");
            int nullIds = 0, nullTitles = 0, invalidConfidence = 0;
            for (Vulnerability vuln : result.getVulnerabilities()) {
                if (vuln.getId() == null) nullIds++;
                if (vuln.getTitle() == null) nullTitles++;
                if (vuln.getConfidence() < 0 || vuln.getConfidence() > 100) invalidConfidence++;
            }
            
            System.out.println("   - Null IDs: " + nullIds);
            System.out.println("   - Null Titles: " + nullTitles);
            System.out.println("   - Invalid Confidence: " + invalidConfidence);
            
            if (nullIds == 0 && nullTitles == 0 && invalidConfidence == 0) {
                System.out.println("   ✅ ВСЕ УЯЗВИМОСТИ КОРРЕКТНЫ!");
            } else {
                System.out.println("   ⚠️ ОБНАРУЖЕНЫ ПРОБЛЕМЫ В ДАННЫХ!");
            }
            
            System.out.println("\n✅ GitHub API тест: УСПЕШЕН");
            
        } catch (Exception e) {
            System.err.println("\n❌ GitHub API тест: ОШИБКА!");
            System.err.println("   " + e.getClass().getSimpleName() + ": " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Тест на Swagger Petstore (стандартный пример)
     */
    private static void testSwaggerPetstore() {
        System.out.println("📦 ТЕСТ 2: Swagger Petstore");
        System.out.println("-".repeat(80));
        
        String petstoreUrl = "https://petstore3.swagger.io/api/v3/openapi.json";
        
        try {
            long startTime = System.currentTimeMillis();
            
            OpenAPIParser parser = new OpenAPIParser();
            parser.parseFromUrl(petstoreUrl);
            
            SecurityScanner scanner = new SecurityScanner(parser, "https://petstore3.swagger.io", false);
            ScanResult result = scanner.scan();
            
            long duration = System.currentTimeMillis() - startTime;
            
            System.out.println("✅ Petstore просканирован за " + duration + " ms");
            System.out.println("   - Эндпоинтов: " + parser.getAllEndpoints().size());
            System.out.println("   - Уязвимостей: " + result.getVulnerabilities().size());
            System.out.println("   - CRITICAL: " + result.getVulnerabilities().stream()
                .filter(v -> v.getSeverity() == Severity.CRITICAL).count());
            System.out.println("   - HIGH: " + result.getVulnerabilities().stream()
                .filter(v -> v.getSeverity() == Severity.HIGH).count());
            
            System.out.println("\n✅ Swagger Petstore тест: УСПЕШЕН");
            
        } catch (Exception e) {
            System.err.println("\n❌ Swagger Petstore тест: ОШИБКА!");
            System.err.println("   " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}
