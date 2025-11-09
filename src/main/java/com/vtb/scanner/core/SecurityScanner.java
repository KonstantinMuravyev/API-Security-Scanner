package com.vtb.scanner.core;

import com.vtb.scanner.models.ScanResult;
import com.vtb.scanner.models.ScanStatistics;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.scanners.*;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;

/**
 * Главный движок сканирования безопасности API
 * Координирует работу всех сканеров уязвимостей
 */
@Slf4j
public class SecurityScanner {
    
    private final OpenAPIParser parser;
    private final String targetUrl;
    private final boolean enableGostChecks;
    
    private final List<VulnerabilityScanner> scanners = new ArrayList<>();
    
    public SecurityScanner(OpenAPIParser parser, String targetUrl, boolean enableGostChecks) {
        this.parser = parser;
        this.targetUrl = targetUrl;
        this.enableGostChecks = enableGostChecks;
        
        initializeScanners();
    }
    
    /**
     * Инициализация всех сканеров
     */
    private void initializeScanners() {
        log.info("Инициализация сканеров безопасности...");
        
        // OWASP API Security Top 10 2023 - Полное покрытие (все 10!)
        scanners.add(new BOLAScanner(targetUrl));               // API1:2023 - BOLA
        scanners.add(new AuthScanner(targetUrl));               // API2:2023 - Broken Authentication
        scanners.add(new PropertyAuthScanner(targetUrl));       // API3:2023 - Broken Property Auth
        scanners.add(new ResourceScanner(targetUrl));           // API4:2023 - Resource Consumption
        scanners.add(new BFLAScanner(targetUrl));               // API5:2023 - BFLA
        scanners.add(new BusinessFlowScanner(targetUrl));       // API6:2023 - Business Flow
        scanners.add(new SSRFScanner(targetUrl));               // API7:2023 - SSRF
        scanners.add(new MisconfigScanner(targetUrl));          // API8:2023 - Misconfiguration
        scanners.add(new InventoryScanner(targetUrl));          // API9:2023 - Improper Inventory
        scanners.add(new UnsafeConsumptionScanner(targetUrl)); // API10:2023 - Unsafe Consumption
        scanners.add(new InjectionScanner(targetUrl));          // + SQL/NoSQL/Command Injection
        
        log.info("Загружено {} сканеров (OWASP API Top 10 покрыт полностью)", scanners.size());
    }
    
    /**
     * Запустить полное сканирование
     * 
     * ИСПОЛЬЗУЕТ VIRTUAL THREADS (Java 21!) для параллельного выполнения!
     * С контекстной адаптацией под тип API!
     */
    public ScanResult scan() {
        log.info("=== Начало сканирования API ===");
        
        // КРИТИЧНО: Проверка parser на null
        if (parser == null) {
            throw new IllegalStateException("Parser не инициализирован");
        }
        
        // КРИТИЧНО: Проверка OpenAPI на null
        OpenAPI openAPI = parser.getOpenAPI();
        if (openAPI == null) {
            throw new IllegalStateException("OpenAPI спецификация не загружена");
        }
        
        log.info("API: {} v{}", parser.getApiTitle(), parser.getApiVersion());
        log.info("Целевой URL: {}", targetUrl);
        log.info("ГОСТ проверки: {}", enableGostChecks ? "Включены" : "Выключены");
        
        // ОПРЕДЕЛЯЕМ КОНТЕКСТ API (банк, медицина, гос и т.д.)
        com.vtb.scanner.semantic.ContextAnalyzer.APIContext context = 
            com.vtb.scanner.semantic.ContextAnalyzer.detectContext(openAPI);
        log.debug("Контекст API определен: {}", context);
        
        // Получаем модификатор severity для этого контекста
        com.vtb.scanner.semantic.ContextAnalyzer.SeverityModifier modifier = 
            com.vtb.scanner.semantic.ContextAnalyzer.getSeverityModifier(context);
        
        // СМАРТ-АНАЛИЗ структуры API!
        Map<String, Object> apiStructure = com.vtb.scanner.heuristics.SmartAnalyzer.analyzeAPIStructure(openAPI);
        log.debug("API Health Score: {}%", apiStructure.get("apiHealthScore"));
        log.debug("Эндпоинтов с auth: {} / {}", 
            apiStructure.get("withAuth"), apiStructure.get("totalEndpoints"));
        
        List<String> anomalies = com.vtb.scanner.heuristics.SmartAnalyzer.findAnomalies(openAPI);
        if (!anomalies.isEmpty()) {
            log.warn("Найдено {} аномалий в структуре API", anomalies.size());
            anomalies.forEach(a -> log.warn("  - {}", a));
        }
        
        log.debug("Параллельное сканирование (Virtual Threads Java 21)");
        
        long startTime = System.currentTimeMillis();
        
        List<Vulnerability> allVulnerabilities = Collections.synchronizedList(new ArrayList<>());
        java.util.concurrent.atomic.AtomicInteger failedScanners = new java.util.concurrent.atomic.AtomicInteger(0);
        
        // ПАРАЛЛЕЛЬНЫЙ запуск всех сканеров через Virtual Threads!
        try (var executor = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            
            java.util.concurrent.CountDownLatch latch = 
                new java.util.concurrent.CountDownLatch(scanners.size());
            
            List<Future<?>> futures = new ArrayList<>();
            
            for (VulnerabilityScanner scanner : scanners) {
                Future<?> future = executor.submit(() -> {
                    try {
                        log.debug("Запуск сканера: {}", scanner.getClass().getSimpleName());
                        List<Vulnerability> vulnerabilities = scanner.scan(openAPI, parser);
                        
                        // ЗАЩИТА ОТ NULL!
                        if (vulnerabilities != null) {
                            // ОПТИМИЗАЦИЯ: Используем synchronized блок для атомарного addAll
                            // Это предотвращает множественные блокировки при большом количестве элементов
                            synchronized (allVulnerabilities) {
                        allVulnerabilities.addAll(vulnerabilities);
                            }
                            log.debug("{} завершен. Найдено: {}", 
                            scanner.getClass().getSimpleName(), vulnerabilities.size());
                        } else {
                            log.warn("{} вернул null вместо списка уязвимостей!", 
                                scanner.getClass().getSimpleName());
                        }
                    } catch (Exception e) {
                        failedScanners.incrementAndGet();
                        log.error("Ошибка в {}: {}", 
                            scanner.getClass().getSimpleName(), e.getMessage(), e);
                    } finally {
                        latch.countDown();
                    }
                });
                futures.add(future);
            }
            
            // Ждем завершения всех сканеров с TIMEOUT!
            // Увеличено до 60 секунд для больших API с множеством эндпоинтов
            boolean completed = latch.await(60, java.util.concurrent.TimeUnit.SECONDS);
            
            if (!completed) {
                log.error("TIMEOUT: Сканеры не завершились за 60 секунд!");
                log.error("Отменяем зависшие задачи...");
                
                // Отменяем все незавершенные задачи
                for (Future<?> future : futures) {
                    if (!future.isDone()) {
                        future.cancel(true);
                        log.warn("Задача отменена из-за timeout");
                    }
                }
            }
            
        } catch (Exception e) {
            log.error("Ошибка параллельного сканирования: {}", e.getMessage(), e);
        }
        
        // Логируем статистику
        if (failedScanners.get() > 0) {
            log.warn("Количество упавших сканеров: {}", failedScanners.get());
        }
        
        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;
        
        // ДЕДУПЛИКАЦИЯ: удаляем дубликаты по endpoint + method + type
        log.debug("Дедупликация уязвимостей...");
        List<Vulnerability> deduplicatedVulnerabilities = deduplicateVulnerabilities(allVulnerabilities);
        int duplicatesRemoved = allVulnerabilities.size() - deduplicatedVulnerabilities.size();
        if (duplicatesRemoved > 0) {
            log.info("Удалено {} дубликатов. Было: {}, стало: {}", 
                duplicatesRemoved, allVulnerabilities.size(), deduplicatedVulnerabilities.size());
        }
        
        // ПРИМЕНЯЕМ КОНТЕКСТНЫЙ МОДИФИКАТОР к уязвимостям!
        log.debug("Применение контекстных правил ({})...", context);
        if (deduplicatedVulnerabilities != null) {
        for (Vulnerability vuln : deduplicatedVulnerabilities) {
                if (vuln == null) continue;
                
            // Если это ГОСТ или Auth проблема - модифицируем severity!
            Severity originalSeverity = vuln.getSeverity();
                if (originalSeverity == null || vuln.getType() == null) continue;
                
            Severity modifiedSeverity = modifier.apply(originalSeverity, vuln.getType().name());
            
            if (modifiedSeverity != originalSeverity) {
                log.debug("Severity повышена: {} → {} для {} (контекст: {})", 
                    originalSeverity, modifiedSeverity, vuln.getType(), context);
                vuln.setSeverity(modifiedSeverity);
                }
            }
        }
        
        // Создание результата
        ScanResult result = buildScanResult(deduplicatedVulnerabilities, duration);
        
        // ИННОВАЦИЯ: Добавляем Attack Surface Map в результат (если нужно)
        // Это можно использовать для дополнительной аналитики
        
        log.info("=== Сканирование завершено ===");
        log.info("Время выполнения: {} мс (ПАРАЛЛЕЛЬНО!)", duration);
        log.info("Всего уязвимостей: {}", deduplicatedVulnerabilities != null ? deduplicatedVulnerabilities.size() : 0);
        
        return result;
    }
    
    /**
     * Дедупликация уязвимостей по endpoint + method + type
     * Оставляет уязвимость с максимальным severity и confidence
     */
    private List<Vulnerability> deduplicateVulnerabilities(List<Vulnerability> vulnerabilities) {
        Map<String, Vulnerability> uniqueVulns = new LinkedHashMap<>();
        
        // КРИТИЧНО: Защита от NPE
        if (vulnerabilities == null) {
            return new ArrayList<>();
        }
        
        for (Vulnerability vuln : vulnerabilities) {
            if (vuln == null) continue;
            
            String key = buildDeduplicationKey(vuln);
            Vulnerability existing = uniqueVulns.get(key);
            
            if (existing == null) {
                uniqueVulns.put(key, vuln);
            } else {
                // Если есть дубликат, выбираем более критичный
                if (shouldReplace(existing, vuln)) {
                    uniqueVulns.put(key, vuln);
                }
            }
        }
        
        return new ArrayList<>(uniqueVulns.values());
    }
    
    /**
     * Создать ключ для дедупликации: endpoint + method + type + paramName + title
     * Добавляем paramName для различения уязвимостей с разными параметрами
     */
    private String buildDeduplicationKey(Vulnerability vuln) {
        // КРИТИЧНО: Защита от NPE
        if (vuln == null) {
            return "NULL|N/A|UNKNOWN||";
        }
        
        String endpoint = vuln.getEndpoint() != null ? vuln.getEndpoint() : "N/A";
        String method = vuln.getMethod() != null ? vuln.getMethod() : "N/A";
        String type = vuln.getType() != null ? vuln.getType().name() : "UNKNOWN";
        
        // Извлекаем имя параметра из title или evidence если возможно
        String paramName = extractParamName(vuln);
        
        // Добавляем title для различения разных уязвимостей на одном эндпоинте
        String title = vuln.getTitle() != null ? vuln.getTitle() : "";
        // Берем первые 50 символов title для уникальности
        String titleKey = title.length() > 50 ? title.substring(0, 50) : title;
        
        // Используем весь ключ для hashCode (не только titleKey!)
        String fullKey = endpoint + "|" + method + "|" + type + "|" + paramName + "|" + titleKey;
        return fullKey;
    }
    
    /**
     * Извлечь имя параметра из уязвимости (из title или evidence)
     */
    private String extractParamName(Vulnerability vuln) {
        // Пытаемся извлечь из title
        String title = vuln.getTitle();
        if (title != null) {
            // Ищем паттерны типа "в параметре 'paramName'" или "parameter 'paramName'"
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
                "параметре\\s+['\"]([^'\"]+)['\"]|parameter\\s+['\"]([^'\"]+)['\"]|в\\s+['\"]([^'\"]+)['\"]");
            java.util.regex.Matcher matcher = pattern.matcher(title);
            if (matcher.find()) {
                for (int i = 1; i <= matcher.groupCount(); i++) {
                    if (matcher.group(i) != null) {
                        return matcher.group(i);
                    }
                }
            }
        }
        
        // Пытаемся извлечь из evidence
        String evidence = vuln.getEvidence();
        if (evidence != null) {
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
                "параметр\\s+['\"]([^'\"]+)['\"]|parameter\\s+['\"]([^'\"]+)['\"]");
            java.util.regex.Matcher matcher = pattern.matcher(evidence);
            if (matcher.find()) {
                for (int i = 1; i <= matcher.groupCount(); i++) {
                    if (matcher.group(i) != null) {
                        return matcher.group(i);
                    }
                }
            }
        }
        
        return "";
    }
    
    /**
     * Определить, нужно ли заменить существующую уязвимость новой
     * Заменяем если новая имеет более высокий severity или confidence
     */
    private boolean shouldReplace(Vulnerability existing, Vulnerability newVuln) {
        // КРИТИЧНО: Защита от NPE
        if (existing == null) return true;
        if (newVuln == null) return false;
        
        // Сравниваем severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)
        int existingSeverity = getSeverityValue(existing.getSeverity());
        int newSeverity = getSeverityValue(newVuln.getSeverity());
        
        if (newSeverity > existingSeverity) {
            return true;
        }
        
        if (newSeverity < existingSeverity) {
            return false;
        }
        
        // При одинаковом severity сравниваем confidence
        // confidence - это int, не Integer, поэтому null-check не нужен
        return newVuln.getConfidence() > existing.getConfidence();
    }
    
    /**
     * Получить числовое значение severity для сравнения
     */
    private int getSeverityValue(Severity severity) {
        if (severity == null) return 0;
        return switch (severity) {
            case CRITICAL -> 5;
            case HIGH -> 4;
            case MEDIUM -> 3;
            case LOW -> 2;
            case INFO -> 1;
        };
    }
    
    /**
     * Построить объект результата сканирования
     */
    private ScanResult buildScanResult(List<Vulnerability> vulnerabilities, long duration) {
        // КРИТИЧНО: Защита от NPE
        int totalEndpoints = 0;
        if (parser != null) {
            Map<String, PathItem> endpoints = parser.getAllEndpoints();
            totalEndpoints = endpoints != null ? endpoints.size() : 0;
        }
        
        ScanStatistics statistics = ScanStatistics.builder()
            .totalEndpoints(totalEndpoints)
            .scannedEndpoints(totalEndpoints)
            .totalVulnerabilities(vulnerabilities != null ? vulnerabilities.size() : 0)
            .criticalVulnerabilities((int) (vulnerabilities != null ? vulnerabilities.stream()
                .filter(v -> v != null && v.getSeverity() != null && v.getSeverity().name().equals("CRITICAL")).count() : 0))
            .highVulnerabilities((int) (vulnerabilities != null ? vulnerabilities.stream()
                .filter(v -> v != null && v.getSeverity() != null && v.getSeverity().name().equals("HIGH")).count() : 0))
            .mediumVulnerabilities((int) (vulnerabilities != null ? vulnerabilities.stream()
                .filter(v -> v != null && v.getSeverity() != null && v.getSeverity().name().equals("MEDIUM")).count() : 0))
            .lowVulnerabilities((int) (vulnerabilities != null ? vulnerabilities.stream()
                .filter(v -> v != null && v.getSeverity() != null && v.getSeverity().name().equals("LOW")).count() : 0))
            .infoVulnerabilities((int) (vulnerabilities != null ? vulnerabilities.stream()
                .filter(v -> v != null && v.getSeverity() != null && v.getSeverity().name().equals("INFO")).count() : 0))
            .scanDurationMs(duration)
            .gostCheckEnabled(enableGostChecks)
            .build();
        
        // Определяем контекст для результата
        OpenAPI openAPIForResult = parser != null ? parser.getOpenAPI() : null;
        com.vtb.scanner.semantic.ContextAnalyzer.APIContext context = 
            openAPIForResult != null ? 
                com.vtb.scanner.semantic.ContextAnalyzer.detectContext(openAPIForResult) :
                com.vtb.scanner.semantic.ContextAnalyzer.APIContext.GENERAL;
        
        // API Health Score из SmartAnalyzer
        long healthScore = 0;
        if (openAPIForResult != null) {
            Map<String, Object> apiStructure = com.vtb.scanner.heuristics.SmartAnalyzer.analyzeAPIStructure(openAPIForResult);
            healthScore = apiStructure != null && apiStructure.get("apiHealthScore") != null ? 
            ((Number)apiStructure.get("apiHealthScore")).longValue() : 0;
        }
        
        return ScanResult.builder()
            .apiName(parser != null ? parser.getApiTitle() : "Unknown")
            .apiVersion(parser != null ? parser.getApiVersion() : "Unknown")
            .targetUrl(targetUrl != null ? targetUrl : "N/A")
            .scanTimestamp(LocalDateTime.now())
            .vulnerabilities(vulnerabilities != null ? vulnerabilities : Collections.emptyList())
            .statistics(statistics)
            .apiContext(context.name())
            .apiHealthScore(healthScore)
            .build();
    }
}

