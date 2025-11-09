package com.vtb.scanner.integration;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.core.SecurityScanner;
import com.vtb.scanner.models.*;

import java.util.*;
import java.util.stream.Collectors;

/**
 * БЫСТРЫЙ ТЕСТ НА РЕАЛЬНЫХ API
 * 
 * Запуск: java -cp target/classes:target/test-classes com.vtb.scanner.integration.QuickRealAPITest
 * 
 * Или через Maven: mvn test -Dtest=QuickRealAPITest
 */
public class QuickRealAPITest {
    
    public static void main(String[] args) {
        System.out.println("🚀 ТЕСТИРОВАНИЕ НА РЕАЛЬНЫХ API\n");
        System.out.println("=".repeat(80));
        
        // Тест 1: Petstore (быстрый)
        testPetstore();
        
        System.out.println("\n" + "=".repeat(80) + "\n");
        
        // Тест 2: GitHub API (критичный, большой файл)
        testGitHubAPI();
        
        System.out.println("\n" + "=".repeat(80));
        System.out.println("✅ ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ!");
    }
    
    private static void testPetstore() {
        System.out.println("📦 ТЕСТ: Swagger Petstore (https://petstore3.swagger.io)");
        System.out.println("-".repeat(80));
        
        String url = "https://petstore3.swagger.io/api/v3/openapi.json";
        
        try {
            long start = System.currentTimeMillis();
            
            OpenAPIParser parser = new OpenAPIParser();
            System.out.println("⏳ Парсинг...");
            parser.parseFromUrl(url);
            long parseTime = System.currentTimeMillis() - start;
            
            System.out.println("✅ Парсинг: " + parseTime + " ms");
            System.out.println("   API: " + parser.getApiTitle() + " v" + parser.getApiVersion());
            System.out.println("   Эндпоинтов: " + parser.getAllEndpoints().size());
            
            System.out.println("\n⏳ Сканирование...");
            SecurityScanner scanner = new SecurityScanner(parser, "https://petstore3.swagger.io", false);
            long scanStart = System.currentTimeMillis();
            ScanResult result = scanner.scan();
            long scanTime = System.currentTimeMillis() - scanStart;
            
            System.out.println("✅ Сканирование: " + scanTime + " ms");
            System.out.println("\n📊 РЕЗУЛЬТАТЫ:");
            System.out.println("   Всего уязвимостей: " + result.getVulnerabilities().size());
            System.out.println("   CRITICAL: " + countBySeverity(result, Severity.CRITICAL));
            System.out.println("   HIGH: " + countBySeverity(result, Severity.HIGH));
            System.out.println("   MEDIUM: " + countBySeverity(result, Severity.MEDIUM));
            System.out.println("   LOW: " + countBySeverity(result, Severity.LOW));
            System.out.println("   API Health Score: " + result.getApiHealthScore());
            System.out.println("   Context: " + result.getApiContext());
            
            // Топ-5 уязвимостей
            System.out.println("\n🚨 ТОП-5 КРИТИЧНЫХ УЯЗВИМОСТЕЙ:");
            result.getVulnerabilities().stream()
                .filter(v -> v.getSeverity() == Severity.CRITICAL || v.getSeverity() == Severity.HIGH)
                .sorted((a, b) -> Integer.compare(b.getConfidence(), a.getConfidence()))
                .limit(5)
                .forEach(v -> System.out.println("   - [" + v.getType() + "] " + v.getTitle() + 
                    " (" + v.getConfidence() + "%)"));
            
        } catch (Exception e) {
            System.err.println("❌ ОШИБКА: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void testGitHubAPI() {
        System.out.println("📦 ТЕСТ: GitHub API (8.8 MB - КРИТИЧНЫЙ ТЕСТ!)");
        System.out.println("-".repeat(80));
        
        String url = "https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json";
        
        try {
            long start = System.currentTimeMillis();
            
            OpenAPIParser parser = new OpenAPIParser();
            System.out.println("⏳ Парсинг большого файла (8.8 MB)...");
            parser.parseFromUrl(url);
            long parseTime = System.currentTimeMillis() - start;
            
            System.out.println("✅ Парсинг: " + parseTime + " ms");
            System.out.println("   API: " + parser.getApiTitle() + " v" + parser.getApiVersion());
            System.out.println("   Эндпоинтов: " + parser.getAllEndpoints().size());
            
            System.out.println("\n⏳ Сканирование большого API...");
            SecurityScanner scanner = new SecurityScanner(parser, "https://api.github.com", false);
            long scanStart = System.currentTimeMillis();
            ScanResult result = scanner.scan();
            long scanTime = System.currentTimeMillis() - scanStart;
            
            System.out.println("✅ Сканирование: " + scanTime + " ms");
            System.out.println("\n📊 РЕЗУЛЬТАТЫ:");
            System.out.println("   Всего уязвимостей: " + result.getVulnerabilities().size());
            System.out.println("   CRITICAL: " + countBySeverity(result, Severity.CRITICAL));
            System.out.println("   HIGH: " + countBySeverity(result, Severity.HIGH));
            System.out.println("   MEDIUM: " + countBySeverity(result, Severity.MEDIUM));
            System.out.println("   API Health Score: " + result.getApiHealthScore());
            System.out.println("   Context: " + result.getApiContext());
            
            // Статистика по типам
            Map<VulnerabilityType, Long> byType = result.getVulnerabilities().stream()
                .collect(Collectors.groupingBy(Vulnerability::getType, Collectors.counting()));
            
            System.out.println("\n🔍 ТОП-10 ТИПОВ УЯЗВИМОСТЕЙ:");
            byType.entrySet().stream()
                .sorted(Map.Entry.<VulnerabilityType, Long>comparingByValue().reversed())
                .limit(10)
                .forEach(entry -> System.out.println("   - " + entry.getKey() + ": " + entry.getValue()));
            
            // Валидация
            long invalid = result.getVulnerabilities().stream()
                .filter(v -> v.getId() == null || v.getTitle() == null || 
                    v.getConfidence() < 0 || v.getConfidence() > 100)
                .count();
            
            if (invalid == 0) {
                System.out.println("\n✅ ВСЕ УЯЗВИМОСТИ КОРРЕКТНЫ!");
            } else {
                System.out.println("\n⚠️ Найдено проблемных уязвимостей: " + invalid);
            }
            
            System.out.println("\n✅ GitHub API тест: УСПЕШЕН! Парсер работает на больших файлах!");
            
        } catch (Exception e) {
            System.err.println("❌ ОШИБКА: " + e.getMessage());
            System.err.println("   Тип ошибки: " + e.getClass().getSimpleName());
            e.printStackTrace();
        }
    }
    
    private static long countBySeverity(ScanResult result, Severity severity) {
        return result.getVulnerabilities().stream()
            .filter(v -> v.getSeverity() == severity)
            .count();
    }
}
