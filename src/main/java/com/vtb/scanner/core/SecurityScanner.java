package com.vtb.scanner.core;

import com.vtb.scanner.analysis.AttackSurfaceMapper;
import com.vtb.scanner.analysis.DataProtectionAnalyzer;
import com.vtb.scanner.analysis.ThreatGraphBuilder;
import com.vtb.scanner.dynamic.DynamicFinding;
import com.vtb.scanner.dynamic.DynamicScanReport;
import com.vtb.scanner.dynamic.DynamicScannerOrchestrator;
import com.vtb.scanner.models.AttackChainSummary;
import com.vtb.scanner.models.AttackSurfaceSummary;
import com.vtb.scanner.models.DataProtectionSummary;
import com.vtb.scanner.models.ExecutiveSummary;
import com.vtb.scanner.models.EntryPointSummary;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.models.ThreatGraph;
import com.vtb.scanner.models.ScanResult;
import com.vtb.scanner.models.ScanStatistics;
import com.vtb.scanner.scanners.*;
import com.vtb.scanner.semantic.ContextAnalyzer;
import com.vtb.scanner.reports.ReportInsights;
import com.vtb.scanner.integration.GOSTGateway;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import java.util.Objects;

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
        scanners.add(new SecretInventoryScanner(targetUrl));    // S14: Secrets & Shadow Inventory
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
        ContextAnalyzer.APIContext context = ContextAnalyzer.detectContext(openAPI);
        log.debug("Контекст API определен: {}", context);
        
        // Получаем модификатор severity для этого контекста
        ContextAnalyzer.SeverityModifier modifier = ContextAnalyzer.getSeverityModifier(context);
        
        // СМАРТ-АНАЛИЗ структуры API!
        Map<String, Object> apiStructure = com.vtb.scanner.heuristics.SmartAnalyzer.analyzeAPIStructure(openAPI);
        log.debug("API Health Score: {}%", apiStructure.get("apiHealthScore"));
        log.debug("Эндпоинтов с auth: {} / {}", 
            apiStructure.get("withAuth"), apiStructure.get("totalEndpoints"));
        Map<String, PathItem> endpointMap = parser.getAllEndpoints();
        int totalEndpoints = endpointMap != null ? endpointMap.size() : 0;
        
        List<String> anomalies = com.vtb.scanner.heuristics.SmartAnalyzer.findAnomalies(openAPI);
        if (!anomalies.isEmpty()) {
            log.warn("Найдено {} аномалий в структуре API", anomalies.size());
            anomalies.forEach(a -> log.warn("  - {}", a));
        }
        
        log.debug("Параллельное сканирование (Virtual Threads Java 21)");
        
        long startTime = System.currentTimeMillis();
        
        List<Vulnerability> allVulnerabilities = Collections.synchronizedList(new ArrayList<>());
        java.util.concurrent.atomic.AtomicInteger failedScanners = new java.util.concurrent.atomic.AtomicInteger(0);
        
        List<VulnerabilityScanner> activeScanners = new ArrayList<>(scanners);
        if (totalEndpoints > 200) {
            int before = activeScanners.size();
            activeScanners.removeIf(scanner ->
                scanner instanceof BusinessFlowScanner ||
                scanner instanceof BFLAScanner ||
                scanner instanceof BOLAScanner);
            int skipped = before - activeScanners.size();
            if (skipped > 0) {
                log.info("Skipping {} heavy scanners for large API ({} endpoints)", skipped, totalEndpoints);
            }
        }
        
        // ПАРАЛЛЕЛЬНЫЙ запуск всех сканеров через Virtual Threads!
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            
            CountDownLatch latch =
                new CountDownLatch(activeScanners.size());
            
            List<Future<?>> futures = new ArrayList<>();
            
            for (VulnerabilityScanner scanner : activeScanners) {
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
            boolean completed = latch.await(60, TimeUnit.SECONDS);
            
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

        for (Vulnerability vulnerability : allVulnerabilities) {
            if (vulnerability != null && vulnerability.getType() == VulnerabilityType.SECURITY_MISCONFIGURATION) {
                String methodKey = vulnerability.getMethod() != null ? vulnerability.getMethod() : "N/A";
                if (!methodKey.contains("|CFG:")) {
                    vulnerability.setMethod(methodKey + "|CFG:" + vulnerability.getId());
                }
            }
        }
        
        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;

        if (enableGostChecks) {
            try {
                GOSTGateway gostGateway = new GOSTGateway(null);
                List<Vulnerability> gostVulnerabilities = gostGateway.checkGostCompliance(openAPI, parser, targetUrl);
                if (!gostVulnerabilities.isEmpty()) {
                    log.info("ГОСТ проверка выявила {} проблем", gostVulnerabilities.size());
                    allVulnerabilities.addAll(gostVulnerabilities);
                } else {
                    log.info("ГОСТ проверка не выявила нарушений");
                }
            } catch (Exception e) {
                log.warn("ГОСТ проверка не выполнена: {}", e.getMessage(), e);
            }
        }
        
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

        if (vuln.getType() == VulnerabilityType.EXCESSIVE_DATA_EXPOSURE ||
            vuln.getType() == VulnerabilityType.SECRET_LEAK) {
            return endpoint + "|" + method + "|" + type;
        }
        
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

        int maxRisk = vulnerabilities != null && !vulnerabilities.isEmpty()
            ? vulnerabilities.stream()
                .filter(Objects::nonNull)
                .mapToInt(Vulnerability::getRiskScore)
                .max()
                .orElse(0)
            : 0;
        double averageRisk = vulnerabilities != null && !vulnerabilities.isEmpty()
            ? vulnerabilities.stream()
                .filter(Objects::nonNull)
                .mapToInt(Vulnerability::getRiskScore)
                .average()
                .orElse(0.0)
            : 0.0;
        Map<String, Long> impactSummary = vulnerabilities != null && !vulnerabilities.isEmpty()
            ? vulnerabilities.stream()
                .filter(v -> v != null && v.getImpactLevel() != null && !v.getImpactLevel().isBlank())
                .collect(Collectors.groupingBy(v -> v.getImpactLevel().split(":")[0], Collectors.counting()))
            : Collections.emptyMap();

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
            .maxRiskScore(maxRisk)
            .averageRiskScore(averageRisk)
            .impactSummary(new HashMap<>(impactSummary))
            .build();
        
        // Определяем контекст для результата
        OpenAPI openAPIForResult = parser != null ? parser.getOpenAPI() : null;
        ContextAnalyzer.APIContext context = 
            openAPIForResult != null ? 
                ContextAnalyzer.detectContext(openAPIForResult) :
                ContextAnalyzer.APIContext.GENERAL;
        
        // API Health Score из SmartAnalyzer
        long healthScore = 0;
        if (openAPIForResult != null) {
            Map<String, Object> apiStructure = com.vtb.scanner.heuristics.SmartAnalyzer.analyzeAPIStructure(openAPIForResult);
            healthScore = apiStructure != null && apiStructure.get("apiHealthScore") != null ? 
            ((Number)apiStructure.get("apiHealthScore")).longValue() : 0;
        }
        
        AttackSurfaceSummary attackSurfaceSummary = buildAttackSurfaceSummary(openAPIForResult);
        DataProtectionSummary dataProtection = DataProtectionAnalyzer.analyze(
            vulnerabilities != null ? vulnerabilities : Collections.emptyList(),
            attackSurfaceSummary,
            context,
            openAPIForResult);
        ThreatGraph threatGraph = ThreatGraphBuilder.build(
            vulnerabilities != null ? vulnerabilities : Collections.emptyList(),
            attackSurfaceSummary,
            dataProtection,
            context);
        DynamicScanReport dynamicScanReport;
        if (shouldRunDynamicScan(attackSurfaceSummary)) {
            dynamicScanReport = new DynamicScannerOrchestrator()
                .execute(targetUrl, attackSurfaceSummary, context);
            correlateDynamicFindings(dynamicScanReport, vulnerabilities);
        } else {
            log.info("Dynamic scanning skipped: attack surface has {} endpoints (threshold {}).",
                attackSurfaceSummary != null ? attackSurfaceSummary.getTotalEndpoints() : 0,
                200);
            dynamicScanReport = DynamicScanReport.empty();
        }
        RiskProfile riskProfile = calculateRiskProfile(statistics, dataProtection, vulnerabilities != null ? vulnerabilities : Collections.emptyList());
        ExecutiveSummary executiveSummary = buildExecutiveSummary(context.name(), statistics, dataProtection,
            vulnerabilities != null ? vulnerabilities : Collections.emptyList(), riskProfile);
        List<String> keyFindings = new ArrayList<>(riskProfile.keyFindings());
        if (dynamicScanReport.hasFindings()) {
            dynamicScanReport.getFindings().stream()
                .limit(5)
                .forEach(finding -> keyFindings.add("Dynamic: " + finding.getDescription()));
        }
        if (dynamicScanReport.getTelemetryNotices() != null) {
            keyFindings.addAll(dynamicScanReport.getTelemetryNotices());
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
            .attackSurface(attackSurfaceSummary)
            .threatGraph(threatGraph)
            .dataProtection(dataProtection)
            .overallRiskScore(riskProfile.score())
            .riskLevel(riskProfile.level())
            .keyFindings(keyFindings)
            .executiveSummary(executiveSummary)
            .dynamicScanReport(dynamicScanReport)
            .build();
    }
    
    private AttackSurfaceSummary buildAttackSurfaceSummary(OpenAPI openAPI) {
        if (openAPI == null || openAPI.getPaths() == null) {
            return AttackSurfaceSummary.builder().build();
        }
        int pathCount = openAPI.getPaths().size();
        if (pathCount > 200) {
            log.info("Attack surface mapping skipped: {} paths exceed threshold {}", pathCount, 200);
            return AttackSurfaceSummary.builder()
                .totalEndpoints(pathCount)
                .build();
        }
        try {
            AttackSurfaceMapper.AttackSurface surface = AttackSurfaceMapper.map(openAPI);
            if (surface == null) {
                return AttackSurfaceSummary.builder().build();
            }

            List<AttackChainSummary> chains = new ArrayList<>();
            if (surface.getAttackChains() != null) {
                for (AttackSurfaceMapper.AttackChain chain : surface.getAttackChains()) {
                    if (chain == null) {
                        continue;
                    }
                    AttackChainSummary summary = AttackChainSummary.builder()
                        .type(nullTo(chain.getType(), "ATTACK_CHAIN"))
                        .target(chain.getTarget())
                        .severity(nullTo(chain.getSeverity(), "UNKNOWN"))
                        .exploitable(chain.isExploitable())
                        .dataSensitivityLevel(chain.getDataSensitivityLevel())
                        .steps(chain.getSteps() != null ? new ArrayList<>(chain.getSteps()) : new ArrayList<>())
                        .sensitiveFields(chain.getSensitiveFields() != null ? new ArrayList<>(chain.getSensitiveFields()) : new ArrayList<>())
                        .metadata(chain.getMetadata() != null ? new LinkedHashMap<>(chain.getMetadata()) : new LinkedHashMap<>())
                        .riskScore(chain.getRiskScore())
                        .signals(chain.getSignals() != null ? new ArrayList<>(new LinkedHashSet<>(chain.getSignals())) : new ArrayList<>())
                        .build();
                    chains.add(summary);
                }
            }

            Map<String, Long> chainsBySeverity = chains.stream()
                .collect(Collectors.groupingBy(
                    c -> c.getSeverity() != null ? c.getSeverity().toUpperCase(Locale.ROOT) : "UNKNOWN",
                    LinkedHashMap::new,
                    Collectors.counting()
                ));

            List<EntryPointSummary> entryPointDetails = new ArrayList<>();
            if (surface.getEntryPointDetails() != null) {
                for (AttackSurfaceMapper.EntryPoint entry : surface.getEntryPointDetails()) {
                    if (entry == null) {
                        continue;
                    }
                    EntryPointSummary entrySummary = EntryPointSummary.builder()
                        .key(entry.getKey())
                        .method(entry.getMethod())
                        .path(entry.getPath())
                        .severity(entry.getSeverity() != null ? entry.getSeverity() : "UNKNOWN")
                        .riskScore(entry.getRiskScore())
                        .requiresAuth(entry.isRequiresAuth())
                        .strongAuth(entry.isStrongAuth())
                        .consentRequired(entry.isConsentRequired())
                        .openBanking(entry.isOpenBanking())
                        .dataSensitivityLevel(entry.getDataSensitivityLevel())
                        .weakProtection(entry.isWeakProtection())
                        .highRisk(entry.isHighRisk())
                        .signals(entry.getSignals() != null ? new ArrayList<>(entry.getSignals()) : new ArrayList<>())
                        .sensitiveFields(entry.getSensitiveFields() != null ? new ArrayList<>(entry.getSensitiveFields()) : new ArrayList<>())
                        .ssrfParameters(entry.getSsrfParameters() != null ? new ArrayList<>(entry.getSsrfParameters()) : new ArrayList<>())
                        .injectionParameters(entry.getInjectionParameters() != null ? new ArrayList<>(entry.getInjectionParameters()) : new ArrayList<>())
                        .privilegeParameters(entry.getPrivilegeParameters() != null ? new ArrayList<>(entry.getPrivilegeParameters()) : new ArrayList<>())
                        .build();
                    entryPointDetails.add(entrySummary);
                }
            }

            int entryPointCount = entryPointDetails.size();
            int maxEntryPointRisk = entryPointDetails.stream()
                .mapToInt(EntryPointSummary::getRiskScore)
                .max()
                .orElse(0);
            double averageEntryPointRisk = entryPointDetails.stream()
                .mapToInt(EntryPointSummary::getRiskScore)
                .average()
                .orElse(0);

            return AttackSurfaceSummary.builder()
                .context(nullTo(surface.getContext(), ContextAnalyzer.APIContext.GENERAL.name()))
                .totalEndpoints(surface.getNodes() != null ? surface.getNodes().size() : 0)
                .relationshipCount(surface.getRelationships() != null ? surface.getRelationships().size() : 0)
                .entryPointCount(entryPointCount)
                .exploitableChains((int) chains.stream().filter(AttackChainSummary::isExploitable).count())
                .entryPoints(surface.getEntryPoints() != null ? new ArrayList<>(surface.getEntryPoints()) : new ArrayList<>())
                .entryPointDetails(entryPointDetails)
                .maxEntryPointRisk(maxEntryPointRisk)
                .averageEntryPointRisk(averageEntryPointRisk)
                .attackChains(chains)
                .chainsBySeverity(chainsBySeverity)
                .build();
        } catch (Exception e) {
            log.warn("Не удалось построить AttackSurfaceSummary: {}", e.getMessage(), e);
            return AttackSurfaceSummary.builder().build();
        }
    }

    private boolean shouldRunDynamicScan(AttackSurfaceSummary summary) {
        if (summary == null) {
            return false;
        }
        if (targetUrl == null || targetUrl.isBlank()) {
            return false;
        }
        if (targetUrl.startsWith("http://")) {
            try {
                URI uri = URI.create(targetUrl);
                String host = uri.getHost();
                if (host == null) {
                    return false;
                }
                String normalizedHost = host.toLowerCase(Locale.ROOT);
                boolean isLocal = normalizedHost.equals("localhost") ||
                    normalizedHost.equals("127.0.0.1") ||
                    normalizedHost.equals("::1");
                if (!isLocal) {
                    log.info("Dynamic scan skipped for non-TLS target {}", targetUrl);
                    return false;
                }
            } catch (IllegalArgumentException ex) {
                log.warn("Invalid target URL {}, skip dynamic scan: {}", targetUrl, ex.getMessage());
                return false;
            }
        }
        return summary.getTotalEndpoints() <= 200;
    }

    private String nullTo(String value, String fallback) {
        return value != null && !value.isBlank() ? value : fallback;
    }

    private RiskProfile calculateRiskProfile(ScanStatistics statistics,
                                             DataProtectionSummary dataProtection,
                                             List<Vulnerability> vulnerabilities) {
        int critical = statistics != null ? statistics.getCriticalVulnerabilities() : 0;
        int high = statistics != null ? statistics.getHighVulnerabilities() : 0;
        int medium = statistics != null ? statistics.getMediumVulnerabilities() : 0;
        int total = statistics != null ? statistics.getTotalVulnerabilities() : vulnerabilities.size();
        int contract = statistics != null ? statistics.getContractViolations() : 0;

        int score = critical * 25 + high * 12 + medium * 6 + contract * 4;
        if (dataProtection != null) {
            score += dataProtection.getCriticalExposures() * 8;
            score += dataProtection.getUnauthorizedFlows() * 5;
            if (dataProtection.getConsentGapCount() > 0) {
                score += 5;
            }
            if (dataProtection.isInsecureTransportDetected()) {
                score += 5;
            }
            if (dataProtection.isStorageExposureDetected()) {
                score += 4;
            }
            if (dataProtection.isLoggingExposureDetected()) {
                score += 3;
            }
        }

        long secretLeaks = vulnerabilities.stream()
            .filter(v -> v != null && v.getType() == VulnerabilityType.SECRET_LEAK)
            .count();
        long shadowApis = vulnerabilities.stream()
            .filter(v -> v != null && v.getType() == VulnerabilityType.SHADOW_API)
            .count();
        score += secretLeaks * 6;
        score += shadowApis * 4;

        score = Math.min(100, score);
        if (total > 0 && score < 10) {
            score = 10;
        }

        String level;
        if (score >= 80) {
            level = "CRITICAL";
        } else if (score >= 60) {
            level = "HIGH";
        } else if (score >= 40) {
            level = "ELEVATED";
        } else if (score >= 20) {
            level = "MODERATE";
        } else {
            level = "LOW";
        }

        List<String> keyFindings = new ArrayList<>();
        if (critical > 0) {
            keyFindings.add("Критичных уязвимостей: " + critical);
        }
        if (high > 0) {
            keyFindings.add("Высоких уязвимостей: " + high);
        }
        if (secretLeaks > 0) {
            keyFindings.add("Найдены потенциальные секреты в спецификации");
        }
        if (shadowApis > 0) {
            keyFindings.add("Обнаружены теневые/dev окружения");
        }
        if (dataProtection != null && dataProtection.getCriticalExposures() > 0) {
            keyFindings.add("PII экспозиции высокого риска: " + dataProtection.getCriticalExposures());
        }
        if (dataProtection != null && dataProtection.isInsecureTransportDetected()) {
            keyFindings.add("Небезопасный транспорт обнаружен для PII/API");
        }
        if (keyFindings.isEmpty() && total == 0) {
            keyFindings.add("Критичных проблем не обнаружено");
        }

        return new RiskProfile(score, level, keyFindings, secretLeaks, shadowApis);
    }

    private ExecutiveSummary buildExecutiveSummary(String context,
                                                   ScanStatistics statistics,
                                                   DataProtectionSummary dataProtection,
                                                   List<Vulnerability> vulnerabilities,
                                                   RiskProfile riskProfile) {
        int critical = statistics != null ? statistics.getCriticalVulnerabilities() : countBySeverity(vulnerabilities, Severity.CRITICAL);
        int high = statistics != null ? statistics.getHighVulnerabilities() : countBySeverity(vulnerabilities, Severity.HIGH);
        int medium = statistics != null ? statistics.getMediumVulnerabilities() : countBySeverity(vulnerabilities, Severity.MEDIUM);
        int low = statistics != null ? statistics.getLowVulnerabilities() : countBySeverity(vulnerabilities, Severity.LOW);
        int info = statistics != null ? statistics.getInfoVulnerabilities() : countBySeverity(vulnerabilities, Severity.INFO);
        int total = statistics != null ? statistics.getTotalVulnerabilities() : vulnerabilities.size();

        int criticalExposures = dataProtection != null ? dataProtection.getCriticalExposures() : 0;
        int consentGaps = dataProtection != null ? dataProtection.getConsentGapCount() : 0;
        int unauthorizedFlows = dataProtection != null ? dataProtection.getUnauthorizedFlows() : 0;

        List<String> recommendedActions = new ArrayList<>();
        if (dataProtection != null && dataProtection.getRecommendedActions() != null) {
            recommendedActions.addAll(dataProtection.getRecommendedActions().stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(action -> !action.isEmpty())
                .toList());
        }
        if (riskProfile.secretLeaks() > 0) {
            recommendedActions.add("Удалить секреты из спецификации и выполнить ротацию ключей");
        }
        if (riskProfile.shadowApis() > 0) {
            recommendedActions.add("Закрыть доступ к dev/test окружениям и исключить их из production спецификаций");
        }

        Map<String, Long> severityBreakdown = new LinkedHashMap<>();
        severityBreakdown.put("CRITICAL", (long) critical);
        severityBreakdown.put("HIGH", (long) high);
        severityBreakdown.put("MEDIUM", (long) medium);
        severityBreakdown.put("LOW", (long) low);
        severityBreakdown.put("INFO", (long) info);

        Map<String, Long> priorityBreakdown = new LinkedHashMap<>();
        for (int p = 1; p <= 5; p++) {
            priorityBreakdown.put("P" + p, 0L);
        }
        if (vulnerabilities != null) {
            for (Vulnerability vuln : vulnerabilities) {
                if (vuln == null) {
                    continue;
                }
                int priority = vuln.getPriority();
                if (priority >= 1 && priority <= 5) {
                    String key = "P" + priority;
                    priorityBreakdown.put(key, priorityBreakdown.get(key) + 1);
                }
            }
        }

        List<ExecutiveSummary.TopFinding> topFindings = new ArrayList<>();
        List<Vulnerability> topCritical = ReportInsights.getTopCriticalVulnerabilities(vulnerabilities, context);
        int limit = Math.min(10, topCritical.size());
        for (int i = 0; i < limit; i++) {
            Vulnerability vuln = topCritical.get(i);
            if (vuln == null) {
                continue;
            }
            topFindings.add(ExecutiveSummary.TopFinding.builder()
                .title(vuln.getTitle())
                .endpoint(vuln.getEndpoint())
                .method(vuln.getMethod())
                .severity(vuln.getSeverity() != null ? vuln.getSeverity().name() : "UNKNOWN")
                .priority(vuln.getPriority())
                .riskScore(vuln.getRiskScore())
                .confidence(vuln.getConfidence())
                .type(vuln.getType() != null ? vuln.getType().name() : "UNKNOWN")
                .build());
        }

        return ExecutiveSummary.builder()
            .riskLevel(riskProfile.level())
            .riskScore(riskProfile.score())
            .apiContext(context)
            .generatedAt(LocalDateTime.now())
            .totalVulnerabilities(total)
            .criticalVulnerabilities(critical)
            .highVulnerabilities(high)
            .mediumVulnerabilities(medium)
            .lowVulnerabilities(low)
            .infoVulnerabilities(info)
            .criticalExposures(criticalExposures)
            .consentGaps(consentGaps)
            .unauthorizedFlows(unauthorizedFlows)
            .secretLeaks((int) riskProfile.secretLeaks())
            .shadowApis((int) riskProfile.shadowApis())
            .keyFindings(new ArrayList<>(riskProfile.keyFindings()))
            .recommendedActions(recommendedActions)
            .topCriticalFindings(topFindings)
            .severityBreakdown(severityBreakdown)
            .priorityBreakdown(priorityBreakdown)
            .build();
    }

    private void correlateDynamicFindings(DynamicScanReport report, List<Vulnerability> vulnerabilities) {
        if (report == null || report.getFindings() == null || vulnerabilities == null || vulnerabilities.isEmpty()) {
            return;
        }
        Map<String, List<Vulnerability>> byKey = new HashMap<>();
        for (Vulnerability vulnerability : vulnerabilities) {
            if (vulnerability == null) {
                continue;
            }
            String key = buildDynamicKey(vulnerability.getMethod(), vulnerability.getEndpoint());
            if (key == null) {
                continue;
            }
            byKey.computeIfAbsent(key, k -> new ArrayList<>()).add(vulnerability);
        }
        for (DynamicFinding finding : report.getFindings()) {
            if (finding == null) {
                continue;
            }
            String key = buildDynamicKey(finding.getMethod(), finding.getEndpoint());
            if (key == null) {
                continue;
            }
            List<Vulnerability> matches = byKey.get(key);
            if (matches == null || matches.isEmpty()) {
                continue;
            }
            List<String> ids = matches.stream()
                .map(Vulnerability::getId)
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(ArrayList::new));
            finding.setRelatedVulnerabilityIds(ids);
        }
    }

    private String buildDynamicKey(String method, String endpoint) {
        String normalizedEndpoint = normalizeDynamicEndpoint(endpoint);
        if (normalizedEndpoint == null) {
            return null;
        }
        String normalizedMethod = method != null ? method.toUpperCase(Locale.ROOT) : "GET";
        return normalizedMethod + " " + normalizedEndpoint;
    }

    private String normalizeDynamicEndpoint(String endpoint) {
        if (endpoint == null) {
            return null;
        }
        String trimmed = endpoint.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            try {
                URI uri = URI.create(trimmed);
                if (uri.getPath() != null && !uri.getPath().isBlank()) {
                    trimmed = uri.getPath();
                }
            } catch (IllegalArgumentException ignored) {
                // fallback
            }
        }
        if (!trimmed.startsWith("/")) {
            trimmed = "/" + trimmed.replaceFirst("^\\./", "");
        }
        return trimmed.replaceAll("/{2,}", "/");
    }

    private int countBySeverity(List<Vulnerability> vulnerabilities, Severity severity) {
        if (vulnerabilities == null) {
            return 0;
        }
        return (int) vulnerabilities.stream()
            .filter(v -> v != null && v.getSeverity() == severity)
            .count();
    }

    private record RiskProfile(int score, String level, List<String> keyFindings, long secretLeaks, long shadowApis) {}
}

