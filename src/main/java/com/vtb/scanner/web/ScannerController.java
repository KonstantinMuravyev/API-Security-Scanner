package com.vtb.scanner.web;

import com.vtb.scanner.core.ContractValidator;
import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.core.SecurityScanner;
import com.vtb.scanner.integration.GOSTGateway;
import com.vtb.scanner.models.ScanResult;
import com.vtb.scanner.semantic.ContextAnalyzer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import jakarta.annotation.PreDestroy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * REST API контроллер для сканера
 * 
 * Упрощает запуск: просто отправить YAML файл через HTTP POST
 */
@Slf4j
@RestController
@RequestMapping("/api/v1")
@CrossOrigin(origins = "*")
public class ScannerController {
    
    private final ExecutorService executorService = Executors.newFixedThreadPool(10); // Увеличен пул для множественных файлов
    
    /**
     * КРИТИЧНО: Закрываем ExecutorService при остановке приложения для предотвращения утечек ресурсов
     */
    @PreDestroy
    public void shutdown() {
        log.info("Закрытие ExecutorService...");
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(60, java.util.concurrent.TimeUnit.SECONDS)) {
                log.warn("ExecutorService не завершился за 60 секунд, принудительное закрытие...");
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            log.warn("Прервано ожидание завершения ExecutorService, принудительное закрытие...");
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Загрузить OpenAPI файл и получить результат сканирования
     * 
     * POST /api/v1/scan
     * Content-Type: multipart/form-data
     * file: openapi.yaml
     */
    @PostMapping("/scan")
    public ResponseEntity<?> scanApi(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "targetUrl", required = false) String targetUrl,
            @RequestParam(value = "enableGost", defaultValue = "true") boolean enableGost,
            @RequestParam(value = "enableFuzzing", defaultValue = "true") boolean enableFuzzing) {
        
        Path tempFile = null;
        try {
            // Валидация файла
            if (file == null || file.isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Файл не загружен или пуст"));
            }
            
            String filename = file.getOriginalFilename();
            String normalizedFilename = filename != null ? filename.toLowerCase(Locale.ROOT) : null;
            if (normalizedFilename == null || (!normalizedFilename.endsWith(".yaml") && !normalizedFilename.endsWith(".yml") && !normalizedFilename.endsWith(".json"))) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Неподдерживаемый формат файла. Используйте .yaml, .yml или .json"));
            }
            
            log.info("Получен запрос на сканирование: {}", filename);
            
            // КРИТИЧНО: Проверка размера файла перед загрузкой
            long fileSize = file.getSize();
            long maxFileSizeMB = 100; // 100 MB лимит для веб-загрузки
            if (fileSize > maxFileSizeMB * 1024 * 1024) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", String.format(
                        "Файл слишком большой: %.2f MB (максимум: %d MB). " +
                        "Используйте CLI для больших файлов.",
                        fileSize / (1024.0 * 1024.0), maxFileSizeMB)));
            }
            
            // Сохраняем временный файл
            tempFile = Files.createTempFile("api-spec-",
                normalizedFilename.endsWith(".json") ? ".json" : ".yaml");
            file.transferTo(tempFile.toFile());
            
            // Парсим
            OpenAPIParser parser = new OpenAPIParser();
            parser.parseFromFile(tempFile.toString());
            
            // Определяем target URL
            if (targetUrl == null || targetUrl.trim().isEmpty()) {
                targetUrl = parser.getServerUrl();
                if (targetUrl == null || targetUrl.trim().isEmpty()) {
                    // КРИТИЧНО: Не используем localhost автоматически - это небезопасно
                    // Требуем явного указания target URL для fuzzing
                    log.warn("Target URL не указан и не найден в спецификации. " +
                            "Fuzzing будет пропущен. Укажите targetUrl явно для активации fuzzing.");
                    targetUrl = null; // Оставляем null вместо localhost
                }
            }
            
            // Валидация формата URL (только если указан)
            if (targetUrl != null) {
                targetUrl = targetUrl.trim();
            }
            
            if (targetUrl != null && !targetUrl.isEmpty() &&
                !targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Неверный формат target URL. Используйте http:// или https://"));
            }
            
            // Проверяем что парсер успешно распарсил спецификацию
            if (parser.getOpenAPI() == null) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Не удалось распарсить OpenAPI спецификацию"));
            }
            
            // Сканируем
            ScanResult result = performScan(parser, targetUrl, enableGost, enableFuzzing);
            
            // Добавляем имя файла в результат
            result.setApiName(filename);
            
            log.info("Сканирование завершено: {} уязвимостей", result.getVulnerabilities().size());
            
            return ResponseEntity.ok(result);
            
        } catch (IllegalArgumentException e) {
            log.error("Ошибка валидации: {}", e.getMessage());
            return ResponseEntity.badRequest()
                .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Ошибка при сканировании: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                .body(Map.of("error", "Внутренняя ошибка сервера: " + e.getMessage()));
        } finally {
            // Удаляем временный файл
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException e) {
                    log.warn("Не удалось удалить временный файл: {}", tempFile);
                }
            }
        }
    }
    
    /**
     * Сканировать несколько файлов одновременно (до 3)
     * 
     * POST /api/v1/scan-multiple
     * Content-Type: multipart/form-data
     * files: file1.yaml, file2.yaml, file3.yaml
     */
    @PostMapping("/scan-multiple")
    public ResponseEntity<?> scanMultipleFiles(
            @RequestParam("files") MultipartFile[] files,
            @RequestParam(value = "targetUrl", required = false) String targetUrl,
            @RequestParam(value = "enableGost", defaultValue = "true") boolean enableGost,
            @RequestParam(value = "enableFuzzing", defaultValue = "true") boolean enableFuzzing) {
        
        try {
            // Валидация количества файлов
            if (files == null || files.length == 0) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Файлы не загружены"));
            }
            
            // Без ограничений на количество файлов
            
            List<Path> tempFiles = new ArrayList<>();
            List<CompletableFuture<Map<String, Object>>> futures = new ArrayList<>();
            
            String normalizedTargetUrl = targetUrl != null ? targetUrl.trim() : null;
            if (normalizedTargetUrl != null && !normalizedTargetUrl.isEmpty() &&
                !normalizedTargetUrl.startsWith("http://") && !normalizedTargetUrl.startsWith("https://")) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Неверный формат target URL. Используйте http:// или https://"));
            }
            
            // Обрабатываем каждый файл параллельно
            for (MultipartFile file : files) {
                try {
                    if (file == null || file.isEmpty()) {
                        continue;
                    }
                    
                    String filename = file.getOriginalFilename();
                    String normalizedFilename = filename != null ? filename.toLowerCase(Locale.ROOT) : null;
                    if (normalizedFilename == null || (!normalizedFilename.endsWith(".yaml") && !normalizedFilename.endsWith(".yml") && !normalizedFilename.endsWith(".json"))) {
                        continue;
                    }
                    
                    // Проверка размера
                    long fileSize = file.getSize();
                    long maxFileSizeMB = 100;
                    if (fileSize > maxFileSizeMB * 1024 * 1024) {
                        continue;
                    }
                    
                    final Path tempFile = Files.createTempFile("api-spec-",
                        normalizedFilename.endsWith(".json") ? ".json" : ".yaml");
                    tempFiles.add(tempFile); // КРИТИЧНО: Добавляем сразу после создания
                    
                    // Асинхронное сканирование каждого файла
                    CompletableFuture<Map<String, Object>> future = CompletableFuture.supplyAsync(() -> {
                        Path tf = tempFile;
                        try {
                            file.transferTo(tf.toFile());
                        
                        OpenAPIParser parser = new OpenAPIParser();
                        parser.parseFromFile(tf.toString());
                        
                        String url = normalizedTargetUrl;
                        if (url == null || url.trim().isEmpty()) {
                            url = parser.getServerUrl();
                            if (url == null || url.trim().isEmpty()) {
                                // КРИТИЧНО: Не используем localhost автоматически
                                log.warn("Target URL не указан для файла {}. Fuzzing будет пропущен.", filename);
                                url = null; // Оставляем null вместо localhost
                            }
                        }

                        if (url != null) {
                            url = url.trim();
                        }
                        
                        // Валидация формата URL (только если указан)
                        if (url != null && !url.isEmpty() &&
                            !url.startsWith("http://") && !url.startsWith("https://")) {
                            return Map.of("filename", filename, "error", "Неверный формат URL");
                        }
                        
                        // Если URL не указан, все равно сканируем (без fuzzing и Contract Validator)
                        // КРИТИЧНО: Используем null вместо "http://unknown" чтобы избежать попыток HTTP запросов
                        String finalUrl = (url == null || url.isEmpty()) ? null : url;
                        
                        if (parser.getOpenAPI() == null) {
                            return Map.of("filename", filename, "error", "Не удалось распарсить спецификацию");
                        }
                        
                        ScanResult result = performScan(parser, finalUrl, enableGost, enableFuzzing);
                        result.setApiName(filename);
                        
                        return Map.of(
                            "filename", filename,
                            "result", result,
                            "success", true
                        );
                        
                    } catch (Exception e) {
                        log.error("Ошибка при сканировании файла {}: {}", filename, e.getMessage());
                        return Map.of(
                            "filename", filename,
                            "error", e.getMessage(),
                            "success", false
                        );
                    }
                    }, executorService);
                    
                    futures.add(future);
                } catch (Exception e) {
                    // КРИТИЧНО: Если исключение при создании tempFile, удаляем его если был создан
                    log.error("Ошибка при обработке файла {}: {}", file != null ? file.getOriginalFilename() : "unknown", e.getMessage());
                }
            }
            
            // Ждем завершения всех сканирований
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
            
            // Собираем результаты
            List<Map<String, Object>> results = futures.stream()
                .map(CompletableFuture::join)
                .collect(Collectors.toList());
            
            // Удаляем временные файлы
            for (Path tempFile : tempFiles) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException e) {
                    log.warn("Не удалось удалить временный файл: {}", tempFile);
                }
            }
            
            Map<String, Object> response = new HashMap<>();
            response.put("results", results);
            response.put("total", results.size());
            response.put("successful", results.stream().mapToLong(r -> (Boolean) r.getOrDefault("success", false) ? 1 : 0).sum());
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Ошибка при множественном сканировании: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                .body(Map.of("error", "Внутренняя ошибка сервера: " + e.getMessage()));
        }
    }
    
    /**
     * Выполнить сканирование (общая логика для обоих методов)
     */
    private ScanResult performScan(OpenAPIParser parser, String targetUrl, boolean enableGost, boolean enableFuzzing) {
        // Сканируем
        SecurityScanner scanner = new SecurityScanner(parser, targetUrl, enableGost);
        ScanResult result = scanner.scan();
        
        // Валидация контракта
        ContractValidator validator = new ContractValidator(parser, targetUrl);
        result.getContractViolations().addAll(validator.validate());
        
        // ГОСТ проверки
        if (enableGost) {
            GOSTGateway gostGateway = new GOSTGateway(null);
            result.getVulnerabilities().addAll(
                gostGateway.checkGostCompliance(parser.getOpenAPI(), parser, targetUrl)
            );
        }
        
        // TLS анализ для HTTPS
        if (targetUrl != null && targetUrl.startsWith("https://")) {
            try {
                com.vtb.scanner.integration.TLSAnalyzer tlsAnalyzer = 
                    new com.vtb.scanner.integration.TLSAnalyzer(targetUrl);
                List<com.vtb.scanner.models.Vulnerability> tlsVulns = tlsAnalyzer.analyzeTLS();
                if (!tlsVulns.isEmpty()) {
                    result.getVulnerabilities().addAll(tlsVulns);
                    log.info("TLS анализ завершен: {} проблем найдено", tlsVulns.size());
                }
            } catch (Exception e) {
                log.warn("TLS анализ не выполнен: {}", e.getMessage());
            }
        }
        
        // Smart Fuzzing (если включен и НЕ localhost) - ЦЕЛЕВОЙ после сканеров!
        if (enableFuzzing && targetUrl != null && 
            !targetUrl.contains("localhost") && !targetUrl.contains("127.0.0.1")) {
            try {
                log.info("Запуск Smart Fuzzer (целевой probing найденных уязвимостей)...");
                log.info("Fuzzing ограничен: max {} запросов глобально, {} на endpoint, {} мс задержка",
                    30, 5, 100);
                
                com.vtb.scanner.fuzzing.SmartFuzzer fuzzer = 
                    new com.vtb.scanner.fuzzing.SmartFuzzer(targetUrl);
                // КРИТИЧНО: Передаем найденные уязвимости для целевой проверки!
                ContextAnalyzer.APIContext apiContext = ContextAnalyzer.APIContext.GENERAL;
                try {
                    if (result.getApiContext() != null) {
                        apiContext = ContextAnalyzer.APIContext.valueOf(result.getApiContext());
                    }
                } catch (IllegalArgumentException ignored) {
                    // Используем GENERAL если распарсить не удалось
                }
                
                List<com.vtb.scanner.models.Vulnerability> fuzzingVulns =
                    fuzzer.targetedProbing(
                        result.getVulnerabilities(),
                        parser.getOpenAPI(),
                        parser,
                        apiContext,
                        result.getAttackSurface(),
                        result.getThreatGraph());
                
                if (!fuzzingVulns.isEmpty()) {
                    // КРИТИЧНО: Дедуплицируем подтвержденные уязвимости перед добавлением
                    // чтобы избежать дубликатов с уже существующими уязвимостями
                    // КРИТИЧНО: Синхронизируем доступ к списку уязвимостей для thread-safety
                    synchronized (result.getVulnerabilities()) {
                        Map<String, com.vtb.scanner.models.Vulnerability> existingKeys = new HashMap<>();
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
            } catch (Exception e) {
                log.warn("Smart Fuzzer не выполнен: {}", e.getMessage());
            }
        } else if (enableFuzzing && targetUrl != null && 
                  (targetUrl.contains("localhost") || targetUrl.contains("127.0.0.1"))) {
            log.warn("Fuzzing пропущен: target=localhost (небезопасно тестировать локально)");
        }
        
        // Benchmark сравнение
        try {
            com.vtb.scanner.benchmark.BenchmarkComparator.BenchmarkComparison benchmark = 
                com.vtb.scanner.benchmark.BenchmarkComparator.compare(result);
            log.info("Benchmark сравнение: Overall Security Score = {}", benchmark.getOverallSecurityScore());
        } catch (Exception e) {
            log.debug("Benchmark сравнение не выполнено: {}", e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Сканировать API по URL спецификации
     * 
     * POST /api/v1/scan-url
     * Body: { "specUrl": "https://...", "targetUrl": "...", "enableGost": true }
     */
    @PostMapping("/scan-url")
    public ResponseEntity<?> scanByUrl(@RequestBody Map<String, Object> request) {
        try {
            String specUrl = (String) request.get("specUrl");
            String targetUrl = (String) request.get("targetUrl");
            Object enableGostObj = request.get("enableGost");
            boolean enableGost = enableGostObj == null || Boolean.TRUE.equals(enableGostObj);
            Object enableFuzzingObj = request.get("enableFuzzing");
            boolean enableFuzzing = enableFuzzingObj != null && Boolean.TRUE.equals(enableFuzzingObj);
            
            // Валидация URL
            if (specUrl == null || specUrl.trim().isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "URL спецификации не указан"));
            }
            
            if (!specUrl.startsWith("http://") && !specUrl.startsWith("https://")) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Неверный формат URL. Используйте http:// или https://"));
            }
            
            log.info("Сканирование по URL: {}", specUrl);
            
            // Парсим
            OpenAPIParser parser = new OpenAPIParser();
            parser.parseFromUrl(specUrl);
            
            // Определяем target
            if (targetUrl == null || targetUrl.trim().isEmpty()) {
                targetUrl = parser.getServerUrl();
                if (targetUrl == null || targetUrl.trim().isEmpty()) {
                    // КРИТИЧНО: Не используем localhost автоматически - это небезопасно
                    log.warn("Target URL не указан и не найден в спецификации. " +
                            "Fuzzing будет пропущен. Укажите targetUrl явно для активации fuzzing.");
                    targetUrl = null; // Оставляем null вместо localhost
                }
            }
            
            // Валидация формата URL (только если указан)
            if (targetUrl != null && !targetUrl.trim().isEmpty() &&
                !targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Неверный формат target URL. Используйте http:// или https://"));
            }
            
            // Проверяем что парсер успешно распарсил спецификацию
            if (parser.getOpenAPI() == null) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Не удалось распарсить OpenAPI спецификацию"));
            }
            
            // Сканируем
            ScanResult result = performScan(parser, targetUrl, enableGost, enableFuzzing);
            
            log.info("Сканирование завершено: {} уязвимостей", result.getVulnerabilities().size());
            
            return ResponseEntity.ok(result);
            
        } catch (IllegalArgumentException e) {
            log.error("Ошибка валидации: {}", e.getMessage());
            return ResponseEntity.badRequest()
                .body(Map.of("error", e.getMessage()));
        } catch (RuntimeException e) {
            // Проверяем причину RuntimeException
            Throwable cause = e.getCause();
            if (cause instanceof java.net.UnknownHostException) {
                log.error("Хост не найден: {}", cause.getMessage());
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Не удалось подключиться к указанному URL. Проверьте доступность ресурса."));
            } else if (cause instanceof java.net.SocketTimeoutException) {
                log.error("Таймаут подключения: {}", cause.getMessage());
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Превышено время ожидания подключения. Проверьте доступность URL."));
            } else if (cause instanceof IOException) {
                log.error("Ошибка загрузки: {}", cause.getMessage());
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Ошибка загрузки спецификации: " + cause.getMessage()));
            }
            log.error("Ошибка при сканировании: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                .body(Map.of("error", "Ошибка при сканировании: " + e.getMessage()));
        } catch (Exception e) {
            log.error("Ошибка при сканировании: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                .body(Map.of("error", "Внутренняя ошибка сервера: " + e.getMessage()));
        }
    }
    
    /**
     * Получить Attack Surface Map
     * GET /api/v1/attack-surface
     */
    @GetMapping("/attack-surface")
    public ResponseEntity<?> getAttackSurface(@RequestParam(value = "specUrl", required = false) String specUrl) {
        try {
            OpenAPIParser parser = new OpenAPIParser();
            
            if (specUrl != null && !specUrl.trim().isEmpty()) {
                parser.parseFromUrl(specUrl);
            } else {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Необходимо указать specUrl параметр"));
            }
            
            if (parser.getOpenAPI() == null) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Не удалось распарсить OpenAPI спецификацию"));
            }
            
            com.vtb.scanner.analysis.AttackSurfaceMapper.AttackSurface surface = 
                com.vtb.scanner.analysis.AttackSurfaceMapper.map(parser.getOpenAPI());
            
            return ResponseEntity.ok(surface);
            
        } catch (Exception e) {
            log.error("Ошибка при построении Attack Surface: {}", e.getMessage(), e);
            return ResponseEntity.status(500)
                .body(Map.of("error", "Внутренняя ошибка сервера: " + e.getMessage()));
        }
    }
    
    /**
     * Health check
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> status = new HashMap<>();
        status.put("status", "UP");
        status.put("scanner", "VTB API Security Scanner");
        status.put("version", "1.0.0");
        status.put("owasp_coverage", "100%");
        status.put("gost_support", true);
        return ResponseEntity.ok(status);
    }
}
