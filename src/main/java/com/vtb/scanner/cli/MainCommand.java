package com.vtb.scanner.cli;

import com.vtb.scanner.core.ContractValidator;
import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.core.SecurityScanner;
import com.vtb.scanner.integration.CICDIntegration;
import com.vtb.scanner.integration.GOSTGateway;
import com.vtb.scanner.models.ScanResult;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.reports.HtmlReportGenerator;
import com.vtb.scanner.reports.JsonReportGenerator;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * Главная CLI команда для сканера безопасности API
 */
@Slf4j
@Command(
    name = "api-scanner",
    mixinStandardHelpOptions = true,
    version = "VTB API Security Scanner 1.0.0",
    description = """
        
        VTB API Security Scanner
        
        Автоматизированный инструмент анализа безопасности и корректности API
        
        Возможности:
          • Анализ уязвимостей OWASP API Top 10
          • Валидация контракта OpenAPI
          • Проверка соответствия ГОСТ стандартам
          • Генерация отчетов (JSON, HTML)
          • Интеграция с CI/CD
        
        """
)
public class MainCommand implements Callable<Integer> {
    
    @Parameters(
        index = "0",
        description = "Путь к файлу OpenAPI спецификации (YAML/JSON) или URL"
    )
    private String specificationPath;
    
    @Option(
        names = {"-u", "--url"},
        description = "Целевой URL API для тестирования (по умолчанию из спецификации)"
    )
    private String targetUrl;
    
    @Option(
        names = {"-o", "--output"},
        description = "Директория для сохранения отчетов (по умолчанию: ./reports)"
    )
    private String outputDir = "./reports";
    
    @Option(
        names = {"--gost"},
        description = "Включить проверку ГОСТ стандартов"
    )
    private boolean enableGost = false;
    
    @Option(
        names = {"--gost-gateway"},
        description = "URL ГОСТ-шлюза для проверки (если не указан - mock режим)"
    )
    private String gostGatewayUrl;
    
    @Option(
        names = {"--preset"},
        description = "Использовать предустановленный профиль (bank-api, gosuslugi, ecommerce)"
    )
    private String preset;
    
    @Option(
        names = {"--json-only"},
        description = "Генерировать только JSON отчет"
    )
    private boolean jsonOnly = false;
    
    @Option(
        names = {"--html-only"},
        description = "Генерировать только HTML отчет"
    )
    private boolean htmlOnly = false;
    
    @Option(
        names = {"--fail-on-high"},
        description = "Прервать с ошибкой при обнаружении HIGH уязвимостей (для CI/CD)"
    )
    private boolean failOnHigh = false;
    
    @Option(
        names = {"--ci"},
        description = "Режим CI/CD (краткий вывод + exit codes)"
    )
    private boolean ciMode = false;
    
    @Option(
        names = {"--web"},
        description = "Запустить веб-интерфейс (http://localhost:8080)"
    )
    private boolean webMode = false;
    
    @Option(
        names = {"--port"},
        description = "Порт для веб-интерфейса (по умолчанию: 8080)"
    )
    private int webPort = 8080;
    
    @Option(
        names = {"--skip-contract"},
        description = "Пропустить валидацию контракта"
    )
    private boolean skipContract = false;
    
    @Option(
        names = {"--fuzzing"},
        description = "Включить gentle fuzzing (БЕЗ DDoS! max 15 запросов с задержками)"
    )
    private boolean enableFuzzing = false;
    
    @Option(
        names = {"--asyncapi"},
        description = "Режим AsyncAPI (для WebSocket/MQTT/Kafka API)"
    )
    private boolean asyncApiMode = false;
    
    public static void main(String[] args) {
        int exitCode = new CommandLine(new MainCommand()).execute(args);
        System.exit(exitCode);
    }
    
    @Override
    public Integer call() throws Exception {
        printBanner();
        
        // Веб-режим
        if (webMode) {
            log.info("Запуск веб-интерфейса на порту {}...", webPort);
            System.out.println("\n╔══════════════════════════════════════════════╗");
            System.out.println("║  Веб-интерфейс запущен!                      ║");
            System.out.println("║                                              ║");
            System.out.println("║  Откройте в браузере:                        ║");
            System.out.println("║  http://localhost:" + webPort + "                        ║");
            System.out.println("║                                              ║");
            System.out.println("║  Просто загрузите YAML и получите отчет!     ║");
            System.out.println("╚══════════════════════════════════════════════╝\n");
            
            // Запускаем Spring Boot
            String[] webArgs = {"--server.port=" + webPort};
            com.vtb.scanner.web.ScannerWebApplication.main(webArgs);
            return 0;
        }
        
        // CLI режим
        try {
            // AsyncAPI режим
            if (asyncApiMode) {
                return scanAsyncAPI();
            }
            
            // 1. Применяем preset если указан
            applyPreset();
            
            // 2. Загружаем и парсим спецификацию
            log.info("Загрузка OpenAPI спецификации: {}", specificationPath);
            OpenAPIParser parser = new OpenAPIParser();
            
            if (specificationPath.startsWith("http://") || specificationPath.startsWith("https://")) {
                parser.parseFromUrl(specificationPath);
            } else {
                parser.parseFromFile(specificationPath);
            }
            
            // Определяем target URL
            if (targetUrl == null || targetUrl.isEmpty()) {
                targetUrl = parser.getServerUrl();
                if (targetUrl == null || targetUrl.isEmpty()) {
                    // КРИТИЧНО: Не используем localhost автоматически - это небезопасно
                    log.warn("Target URL не указан и не найден в спецификации. " +
                            "Fuzzing будет пропущен. Укажите --url для активации fuzzing.");
                    targetUrl = null; // Оставляем null вместо localhost
                }
            }
            
            // Валидация формата URL (только если указан)
            if (targetUrl != null && !targetUrl.isEmpty() &&
                !targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
                log.error("Неверный формат target URL: {}", targetUrl);
                throw new IllegalArgumentException("Target URL должен начинаться с http:// или https://");
            }
            
            if (targetUrl != null && !targetUrl.isEmpty()) {
                log.info("Целевой URL: {}", targetUrl);
            } else {
                log.info("Целевой URL: не указан (fuzzing будет пропущен)");
            }
            
            // КРИТИЧНО: Проверка что парсинг успешен перед дальнейшей работой
            if (parser.getOpenAPI() == null) {
                log.error("Не удалось распарсить OpenAPI спецификацию");
                throw new IllegalStateException("OpenAPI спецификация не загружена. Проверьте формат файла.");
            }
            
            // 2.5. АВТОМАТИЧЕСКОЕ ОПРЕДЕЛЕНИЕ ГОСТ
            boolean autoDetectedGost = GOSTGateway.shouldCheckGOST(parser.getOpenAPI(), targetUrl);
            
            // Если ГОСТ не указан явно, но обнаружен автоматически - включаем
            if (!enableGost && autoDetectedGost) {
                log.info("Автоматически обнаружен ГОСТ в спецификации - включаем проверку");
                enableGost = true;
            }
            
            // Если указан --gost, но ГОСТ не найден - просто предупреждение, но продолжаем работу
            if (enableGost && !autoDetectedGost && !GOSTGateway.isGOSTCompliant(parser.getOpenAPI())) {
                log.warn("ВНИМАНИЕ: Указан флаг --gost, но в спецификации не найдено упоминаний ГОСТ!");
                log.warn("   Сканирование продолжится, но ГОСТ проверки могут быть неполными.");
                log.warn("   Рекомендация: добавьте описание ГОСТ в спецификацию или используйте --preset bank-api");
            }
            
            // Если ГОСТ не обнаружен - просто пометка
            if (!enableGost && !autoDetectedGost) {
                log.info("ГОСТ не обнаружен в спецификации - стандартное сканирование");
            }
            
            // 3. Запускаем сканирование безопасности
            log.info("Запуск сканирования безопасности...");
            SecurityScanner scanner = new SecurityScanner(parser, targetUrl, enableGost);
            ScanResult result = scanner.scan();
            
            // 4. Валидация контракта (опционально)
            if (!skipContract) {
                log.info("Валидация контракта API...");
                ContractValidator validator = new ContractValidator(parser, targetUrl);
                result.getContractViolations().addAll(validator.validate());
            }
            
            // 5. ГОСТ проверки (если включены)
            if (enableGost) {
                log.info("Проверка соответствия ГОСТ стандартам...");
                GOSTGateway gostGateway = new GOSTGateway(gostGatewayUrl);
                result.getVulnerabilities().addAll(
                    gostGateway.checkGostCompliance(parser.getOpenAPI(), parser, targetUrl)
                );
            }
            
            // 5b. Smart Fuzzing (если включен и НЕ localhost) - ЦЕЛЕВОЙ после сканеров!
            if (enableFuzzing && targetUrl != null && !targetUrl.isEmpty() &&
                !targetUrl.contains("localhost") && !targetUrl.contains("127.0.0.1")) {
                log.info("Запуск Smart Fuzzer (целевой probing найденных уязвимостей)...");
                log.info("Fuzzing ограничен: max {} запросов глобально, {} на endpoint, {} мс задержка", 
                    30, 5, 500);
                
                com.vtb.scanner.fuzzing.SmartFuzzer fuzzer = 
                    new com.vtb.scanner.fuzzing.SmartFuzzer(targetUrl);
                // КРИТИЧНО: Передаем найденные уязвимости для целевой проверки!
                List<com.vtb.scanner.models.Vulnerability> fuzzingVulns = 
                    fuzzer.targetedProbing(result.getVulnerabilities(), parser.getOpenAPI(), parser);
                
                if (!fuzzingVulns.isEmpty()) {
                    // КРИТИЧНО: Дедуплицируем подтвержденные уязвимости перед добавлением
                    // чтобы избежать дубликатов с уже существующими уязвимостями
                    // КРИТИЧНО: Синхронизируем доступ к списку уязвимостей для thread-safety
                    synchronized (result.getVulnerabilities()) {
                        java.util.Map<String, com.vtb.scanner.models.Vulnerability> existingKeys = new java.util.HashMap<>();
                        for (com.vtb.scanner.models.Vulnerability existing : result.getVulnerabilities()) {
                            if (existing != null && existing.getEndpoint() != null && existing.getMethod() != null && existing.getType() != null) {
                                String key = String.format("%s|%s|%s", 
                                    existing.getEndpoint(), existing.getMethod(), existing.getType().name());
                                existingKeys.put(key, existing);
                            }
                        }
                        
                        // Добавляем только уникальные подтвержденные уязвимости
                        int added = 0;
                        for (com.vtb.scanner.models.Vulnerability fuzzingVuln : fuzzingVulns) {
                            if (fuzzingVuln != null && fuzzingVuln.getEndpoint() != null && 
                                fuzzingVuln.getMethod() != null && fuzzingVuln.getType() != null) {
                                String key = String.format("%s|%s|%s", 
                                    fuzzingVuln.getEndpoint(), fuzzingVuln.getMethod(), fuzzingVuln.getType().name());
                                
                                // Если уязвимость уже существует, заменяем ее на подтвержденную (с более высоким confidence)
                                com.vtb.scanner.models.Vulnerability existing = existingKeys.get(key);
                                if (existing != null) {
                                    // Заменяем существующую на подтвержденную (у нее выше confidence)
                                    if (fuzzingVuln.getConfidence() > existing.getConfidence()) {
                                        result.getVulnerabilities().remove(existing);
                                        result.getVulnerabilities().add(fuzzingVuln);
                                        added++;
                                    }
                                } else {
                                    // Добавляем новую подтвержденную уязвимость
                                    result.getVulnerabilities().add(fuzzingVuln);
                                    added++;
                                }
                            }
                        }
                        
                        log.info("Smart Fuzzer завершен: {} подтвержденных уязвимостей добавлено ({} было найдено)", 
                            added, fuzzingVulns.size());
                    }
                } else {
                    log.info("Smart Fuzzer завершен: уязвимости не подтверждены через реальные запросы");
                }
            } else if (enableFuzzing) {
                log.warn("Fuzzing пропущен: target=localhost (небезопасно тестировать локально)");
            }
            
            // 6. Генерация отчетов
            log.info("📊 Генерация отчетов...");
            Path outputPath = Paths.get(outputDir);
            outputPath.toFile().mkdirs();
            
            if (!htmlOnly) {
                JsonReportGenerator jsonGen = new JsonReportGenerator();
                jsonGen.generate(result, outputPath.resolve("scan-report.json"));
            }
            
            if (!jsonOnly) {
                HtmlReportGenerator htmlGen = new HtmlReportGenerator();
                htmlGen.generate(result, outputPath.resolve("scan-report.html"));
                
                // PDF отчет (требование хакатона!)
                log.info("Генерация PDF отчета...");
                com.vtb.scanner.reports.PdfReportGenerator pdfGen = 
                    new com.vtb.scanner.reports.PdfReportGenerator();
                pdfGen.generate(result, outputPath.resolve("scan-report.pdf"));
                
                // ИННОВАЦИЯ: Attack Surface Map
                log.info("🗺️ Построение карты поверхности атаки...");
                com.vtb.scanner.analysis.AttackSurfaceMapper.AttackSurface surface = 
                    com.vtb.scanner.analysis.AttackSurfaceMapper.map(parser.getOpenAPI());
                
                com.vtb.scanner.reports.AttackSurfaceReportGenerator surfaceGen = 
                    new com.vtb.scanner.reports.AttackSurfaceReportGenerator();
                surfaceGen.generate(surface, outputPath.resolve("attack-surface.html"));
            }
            
            // 7. Вывод результатов
            if (ciMode) {
                CICDIntegration.printCISummary(result);
                return CICDIntegration.getExitCode(result, failOnHigh);
            } else {
                printDetailedResults(result);
            }
            
            // 8. Определяем exit code
            if (result.hasCriticalVulnerabilities()) {
                log.error("Обнаружены критичные уязвимости!");
                return 1;
            }
            
            if (failOnHigh && result.getVulnerabilityCountBySeverity(
                com.vtb.scanner.models.Severity.HIGH) > 0) {
                log.error("Обнаружены HIGH уязвимости (--fail-on-high)");
                return 1;
            }
            
            log.info("Сканирование завершено успешно");
            return 0;
            
        } catch (Exception e) {
            log.error("Ошибка при сканировании: {}", e.getMessage(), e);
            return 1;
        }
    }
    
    /**
     * Применить предустановленный профиль
     */
    private void applyPreset() {
        if (preset == null) return;
        
        log.info("🎨 Применение preset: {}", preset);
        
        switch (preset.toLowerCase()) {
            case "bank-api":
                enableGost = true;
                log.info("  - Включены ГОСТ проверки");
                log.info("  - Строгие проверки аутентификации");
                break;
                
            case "gosuslugi":
                enableGost = true;
                failOnHigh = true;
                log.info("  - Включены ГОСТ проверки");
                log.info("  - Строгий режим (fail-on-high)");
                break;
                
            case "ecommerce":
                log.info("  - Проверки платежных данных");
                log.info("  - Проверки персональных данных");
                break;
                
            default:
                log.warn("Неизвестный preset: {}", preset);
        }
    }
    
    /**
     * Вывести детальные результаты
     */
    private void printDetailedResults(ScanResult result) {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("VTB API SECURITY SCAN REPORT");
        System.out.println("=".repeat(80));
        System.out.println();
        System.out.println("API: " + result.getApiName() + " v" + result.getApiVersion());
        System.out.println("URL: " + result.getTargetUrl());
        System.out.println("📅 Дата: " + result.getScanTimestamp());
        System.out.println("⏱️  Время сканирования: " + result.getStatistics().getScanDurationMs() + " мс");
        System.out.println();
        System.out.println("📊 СТАТИСТИКА:");
        System.out.println("   Всего эндпоинтов: " + result.getStatistics().getTotalEndpoints());
        System.out.println("   Всего уязвимостей: " + result.getVulnerabilities().size());
        System.out.println();
        System.out.println("CRITICAL: " + result.getVulnerabilityCountBySeverity(
            com.vtb.scanner.models.Severity.CRITICAL));
        System.out.println("HIGH:     " + result.getVulnerabilityCountBySeverity(
            com.vtb.scanner.models.Severity.HIGH));
        System.out.println("MEDIUM:   " + result.getVulnerabilityCountBySeverity(
            com.vtb.scanner.models.Severity.MEDIUM));
        System.out.println("LOW:      " + result.getVulnerabilityCountBySeverity(
            com.vtb.scanner.models.Severity.LOW));
        System.out.println("INFO:     " + result.getVulnerabilityCountBySeverity(
            com.vtb.scanner.models.Severity.INFO));
        System.out.println();
        
        if (enableGost) {
            long gostVulns = result.getVulnerabilities().stream()
                .filter(v -> v.isGostRelated())
                .count();
            System.out.println("ГОСТ нарушений: " + gostVulns);
            System.out.println();
        }
        
        // Топ-5 уязвимостей
        if (!result.getVulnerabilities().isEmpty()) {
            System.out.println("ТОП УЯЗВИМОСТИ:");
            result.getVulnerabilities().stream()
                .limit(5)
                .forEach(v -> {
                    System.out.printf("   [%s] %s%n", 
                        getSeverityEmoji(v.getSeverity()), 
                        v.getTitle());
                    System.out.printf("      → %s [%s]%n", 
                        v.getEndpoint(), 
                        v.getMethod());
                });
        }
        
        System.out.println();
        System.out.println("Отчеты сохранены в: " + outputDir);
        System.out.println("=".repeat(80));
        System.out.println();
    }
    
    private String getSeverityEmoji(com.vtb.scanner.models.Severity severity) {
        return switch (severity) {
            case CRITICAL -> "CRITICAL";
            case HIGH -> "HIGH";
            case MEDIUM -> "MEDIUM";
            case LOW -> "LOW";
            case INFO -> "INFO";
        };
    }
    
    /**
     * Сканирование AsyncAPI
     */
    private Integer scanAsyncAPI() {
        log.info("Режим AsyncAPI");
        
        try {
            com.vtb.scanner.asyncapi.AsyncAPIParser asyncParser = 
                new com.vtb.scanner.asyncapi.AsyncAPIParser();
            asyncParser.parseFromFile(specificationPath);
            
            com.vtb.scanner.asyncapi.AsyncAPIScanner asyncScanner = 
                new com.vtb.scanner.asyncapi.AsyncAPIScanner(asyncParser);
            
            List<Vulnerability> vulns = asyncScanner.scan();
            
            System.out.println("\n=== AsyncAPI Security Scan ===");
            System.out.println("API: " + asyncParser.getInfo().getTitle());
            System.out.println("Версия: " + asyncParser.getInfo().getVersion());
            System.out.println("Уязвимостей найдено: " + vulns.size());
            System.out.println("\nAsyncAPI 2.6+ поддержка работает!");
            
            return vulns.isEmpty() ? 0 : 1;
            
        } catch (Exception e) {
            log.error("Ошибка AsyncAPI сканирования: {}", e.getMessage());
            return 1;
        }
    }
    
    /**
     * Вывести баннер
     */
    private void printBanner() {
        if (ciMode) return;  // Не показываем в CI режиме
        
        System.out.println("""
            
            ╔═══════════════════════════════════════════════════════════╗
            ║                                                           ║
            ║     VTB API Security Scanner v1.0.0                   ║
            ║                                                           ║
            ║     Автоматизированный анализ безопасности API            ║
            ║     • OWASP API Top 10                                    ║
            ║     • ГОСТ стандарты                                      ║
            ║     • Валидация контракта                                 ║
            ║                                                           ║
            ╚═══════════════════════════════════════════════════════════╝
            
            """);
    }
}

