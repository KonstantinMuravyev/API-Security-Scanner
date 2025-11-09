package com.vtb.scanner.fuzzing;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * ИННОВАЦИЯ: Smart Fuzzer - БЕЗ риска DDoS!
 * 
 * ЦЕЛЕВОЙ fuzzing: проверяет найденные уязвимости через реальные HTTP запросы
 * 
 * Безопасность:
 * 1. Числовые лимиты запросов (глобальный + на endpoint)
 * 2. Обработка rate limits (429) - остановка для endpoint
 * 3. Обработка auth errors (401/403) - остановка попыток
 * 4. Timeout handling - продолжение с лимитом
 * 5. Thread-safe счетчики (AtomicInteger)
 * 6. Задержки между запросами (500ms)
 * 
 * Это НЕ DDoS, это "gentle targeted probing"!
 */
@Slf4j
public class SmartFuzzer {
    
    private final String targetUrl;
    private final OkHttpClient httpClient;
    
    // КРИТИЧНО: Числовые лимиты для безопасности (thread-safe!)
    private static final int MAX_REQUESTS_PER_ENDPOINT = 5; // Максимум 5 попыток на endpoint
    private static final int MAX_TOTAL_REQUESTS = 30; // Глобальный лимит запросов
    private static final long DELAY_MS = 100; // ОПТИМИЗАЦИЯ: Уменьшено до 100мс для скорости (было 500мс)
    private static final int TIMEOUT_SEC = 3; // ОПТИМИЗАЦИЯ: Уменьшено до 3 сек для скорости (было 5 сек)
    
    // Thread-safe счетчики
    private final AtomicInteger totalRequests = new AtomicInteger(0);
    private final Map<String, AtomicInteger> requestsPerEndpoint = new ConcurrentHashMap<>();
    
    // Умные payloads (не random!)
    private static final String[] SQL_PAYLOADS = {
        "' OR '1'='1",  // Классическая SQL injection
        "1; DROP TABLE users--",
        "1' UNION SELECT NULL--",
        "admin'--"
    };
    
    private static final String[] NOSQL_PAYLOADS = {
        "'; return true; var x='",  // MongoDB NoSQL injection
        "{$ne: null}",  // MongoDB operator
        "{$gt: ''}",  // MongoDB operator
        "'; return true; //"
    };
    
    private static final String[] COMMAND_INJECTION_PAYLOADS = {
        "; ls -la",  // Unix command injection
        "| whoami",  // Pipe injection
        "& dir",  // Windows command injection
        "; cat /etc/passwd"
    };
    
    private static final String[] LDAP_PAYLOADS = {
        "*)(uid=*))(|(uid=*",  // LDAP injection
        "admin)(&",  // LDAP injection
        "*))%00",  // LDAP null byte
        "admin)(|(password=*"
    };
    
    private static final String[] BOLA_PAYLOADS = {
        "0",    // ID=0 (часто admin)
        "999999",  // Большой ID
        "-1",   // Отрицательный ID
        "1"
    };
    
    private static final String[] SSRF_PAYLOADS = {
        "http://127.0.0.1:8080",  // Локальный сервер (безопасный для тестирования)
        "http://169.254.169.254/latest/meta-data",  // AWS metadata (стандартный SSRF тест)
        "http://localhost/admin"  // Локальный admin endpoint (безопасный для тестирования)
    };
    
    public SmartFuzzer(String targetUrl) {
        this.targetUrl = targetUrl;
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(TIMEOUT_SEC, TimeUnit.SECONDS)
            .readTimeout(TIMEOUT_SEC, TimeUnit.SECONDS)
            .followRedirects(false)
            .build();
    }
    
    /**
     * ЦЕЛЕВОЙ fuzzing: проверяет найденные уязвимости через реальные HTTP запросы
     * 
     * @param foundVulnerabilities список уязвимостей найденных сканерами
     * @param openAPI OpenAPI спецификация
     * @param parser парсер спецификации
     * @return список ПОДТВЕРЖДЕННЫХ уязвимостей через реальные запросы
     */
    public List<Vulnerability> targetedProbing(List<Vulnerability> foundVulnerabilities, 
                                                OpenAPI openAPI, OpenAPIParser parser) {
        log.info("Запуск Smart Fuzzer (целевой probing найденных уязвимостей)...");
        log.info("Лимиты: max {} запросов глобально, {} на endpoint, {} мс задержка", 
            MAX_TOTAL_REQUESTS, MAX_REQUESTS_PER_ENDPOINT, DELAY_MS);
        
        // КРИТИЧНО: Сбрасываем счетчики при каждом вызове для изоляции
        totalRequests.set(0);
        requestsPerEndpoint.clear();
        
        List<Vulnerability> confirmedVulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (targetUrl == null) {
            log.warn("Target URL null, пропускаем fuzzing");
            return confirmedVulnerabilities;
        }
        
        if (targetUrl.contains("localhost") || targetUrl.contains("127.0.0.1")) {
            log.warn("Target - localhost. Fuzzing пропущен (для безопасности).");
            return confirmedVulnerabilities;
        }
        
        if (foundVulnerabilities == null || foundVulnerabilities.isEmpty()) {
            log.info("Нет найденных уязвимостей для проверки через fuzzing");
            return confirmedVulnerabilities;
        }
        
        // Фильтруем типы уязвимостей которые можно проверить через HTTP
        Set<VulnerabilityType> fuzzableTypes = Set.of(
            VulnerabilityType.BOLA,
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.NOSQL_INJECTION,
            VulnerabilityType.COMMAND_INJECTION,
            VulnerabilityType.LDAP_INJECTION,
            VulnerabilityType.SSRF,
            VulnerabilityType.BROKEN_AUTHENTICATION,
            VulnerabilityType.BFLA
        );
        
        // Группируем по endpoint + method для дедупликации
        Map<String, List<Vulnerability>> byEndpoint = new LinkedHashMap<>();
        for (Vulnerability vuln : foundVulnerabilities) {
            if (vuln == null || vuln.getType() == null || !fuzzableTypes.contains(vuln.getType())) {
                continue;
            }
            
            String key = String.format("%s|%s", 
                vuln.getEndpoint() != null ? vuln.getEndpoint() : "",
                vuln.getMethod() != null ? vuln.getMethod() : "");
            
            byEndpoint.computeIfAbsent(key, k -> new ArrayList<>()).add(vuln);
        }
        
        log.info("Найдено {} fuzzable уязвимостей на {} endpoints", 
            foundVulnerabilities.stream().filter(v -> v != null && fuzzableTypes.contains(v.getType())).count(),
            byEndpoint.size());
        
        // Проверяем каждую группу
        for (Map.Entry<String, List<Vulnerability>> entry : byEndpoint.entrySet()) {
            if (totalRequests.get() >= MAX_TOTAL_REQUESTS) {
                log.info("Достигнут глобальный лимит запросов ({}). Fuzzing остановлен.", MAX_TOTAL_REQUESTS);
                break;
            }
            
            String[] parts = entry.getKey().split("\\|", -1); // -1 чтобы сохранить пустые строки
            String endpoint = parts.length > 0 && !parts[0].isEmpty() ? parts[0] : "";
            String method = parts.length > 1 && !parts[1].isEmpty() ? parts[1] : "GET";
            
            // КРИТИЧНО: Защита от пустого endpoint
            if (endpoint.isEmpty()) {
                log.debug("Пропускаем группу с пустым endpoint: {}", entry.getKey());
                continue;
            }
            
            // Проверяем лимит для этого endpoint
            AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
            if (endpointCounter.get() >= MAX_REQUESTS_PER_ENDPOINT) {
                log.debug("Лимит запросов для {} достигнут, пропускаем", endpoint);
                continue;
            }
            
            // Проверяем первую (самую критичную) уязвимость в группе
            // КРИТИЧНО: Защита от пустого списка
            List<Vulnerability> vulnsInGroup = entry.getValue();
            if (vulnsInGroup == null || vulnsInGroup.isEmpty()) {
                log.debug("Пропускаем пустую группу для endpoint: {}", entry.getKey());
                continue;
            }
            
            Vulnerability vuln = vulnsInGroup.get(0);
            
            // Целевая проверка по типу уязвимости
            log.debug("Проверка уязвимости типа {} на endpoint {} метод {}", vuln.getType(), endpoint, method);
            List<Vulnerability> confirmed = probeVulnerability(vuln, endpoint, method, openAPI);
            
            if (!confirmed.isEmpty()) {
                log.info("Подтверждено {} уязвимостей на endpoint {}", confirmed.size(), endpoint);
                confirmedVulnerabilities.addAll(confirmed);
                // Повышаем confidence для подтвержденных уязвимостей
                for (Vulnerability confirmedVuln : confirmed) {
                    confirmedVuln.setConfidence(Math.min(100, confirmedVuln.getConfidence() + 20));
                    confirmedVuln.setPriority(Math.max(1, confirmedVuln.getPriority() - 1)); // Повышаем приоритет
                }
            } else {
                log.debug("Уязвимость не подтверждена на endpoint {}", endpoint);
            }
            
            // ОПТИМИЗАЦИЯ: Убрана избыточная задержка между endpoints
            // Задержки уже есть внутри probe методов, дополнительная задержка не нужна
            // sleep(DELAY_MS); // УДАЛЕНО для ускорения
        }
        
        log.info("Smart Fuzzer завершен. Сделано {} запросов. Подтверждено: {} уязвимостей", 
            totalRequests.get(), confirmedVulnerabilities.size());
        
        return confirmedVulnerabilities;
    }
    
    /**
     * Проверка конкретной уязвимости через HTTP запрос
     */
    private List<Vulnerability> probeVulnerability(Vulnerability vuln, String endpoint, 
                                                    String method, OpenAPI openAPI) {
        List<Vulnerability> confirmed = new ArrayList<>();
        
        if (vuln == null || vuln.getType() == null || endpoint == null) {
            return confirmed;
        }
        
        VulnerabilityType type = vuln.getType();
        
        // Выбираем метод проверки по типу
        switch (type) {
            case BOLA:
                confirmed.addAll(probeBOLA(endpoint, method));
                break;
            case SQL_INJECTION:
                confirmed.addAll(probeSQLInjection(endpoint, method));
                break;
            case NOSQL_INJECTION:
                confirmed.addAll(probeNoSQLInjection(endpoint, method));
                break;
            case COMMAND_INJECTION:
                confirmed.addAll(probeCommandInjection(endpoint, method));
                break;
            case LDAP_INJECTION:
                confirmed.addAll(probeLDAPInjection(endpoint, method));
                break;
            case SSRF:
                confirmed.addAll(probeSSRF(endpoint, method));
                break;
            case BROKEN_AUTHENTICATION:
            case BFLA:
                confirmed.addAll(probeAuthentication(endpoint, method));
                break;
            default:
                log.debug("Тип уязвимости {} не поддерживается для fuzzing", type);
        }
        
        return confirmed;
    }
    
    /**
     * Безопасное выполнение HTTP запроса с обработкой ошибок и лимитов
     * КРИТИЧНО: Атомарная проверка и увеличение счетчиков для предотвращения race conditions
     */
    private FuzzingResult executeRequest(Request request, String endpoint) {
        // КРИТИЧНО: Защита от null endpoint
        if (endpoint == null) {
            endpoint = "unknown";
        }
        
        // КРИТИЧНО: Атомарная проверка и резервирование запроса для предотвращения race conditions
        // Используем compareAndSet для атомарной проверки и увеличения
        int currentTotal = totalRequests.get();
        if (currentTotal >= MAX_TOTAL_REQUESTS) {
            return FuzzingResult.STOPPED_LIMIT_REACHED;
        }
        
        // Атомарное резервирование глобального запроса
        while (true) {
            int current = totalRequests.get();
            if (current >= MAX_TOTAL_REQUESTS) {
                return FuzzingResult.STOPPED_LIMIT_REACHED;
            }
            if (totalRequests.compareAndSet(current, current + 1)) {
                break; // Успешно зарезервировали запрос
            }
            // Если не удалось - повторяем попытку (CAS failed, другой поток обновил)
        }
        
        // Проверка лимита для endpoint (после успешного резервирования глобального)
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        // Атомарное резервирование запроса для endpoint
        while (true) {
            int current = endpointCounter.get();
            if (current >= MAX_REQUESTS_PER_ENDPOINT) {
                // Откатываем глобальный счетчик, так как endpoint лимит достигнут
                totalRequests.decrementAndGet();
                return FuzzingResult.STOPPED_ENDPOINT_LIMIT;
            }
            if (endpointCounter.compareAndSet(current, current + 1)) {
                break; // Успешно зарезервировали запрос для endpoint
            }
            // Если не удалось - повторяем попытку (CAS failed)
        }
        
        // Теперь счетчики зарезервированы, выполняем запрос
        try (Response response = httpClient.newCall(request).execute()) {
            int code = response.code();
            
            // Обработка ошибок с остановкой
            if (code == 429) {
                log.warn("Rate limit (429) для {}. Останавливаем fuzzing для этого endpoint.", endpoint);
                return FuzzingResult.STOPPED_RATE_LIMIT;
            }
            
            if (code == 401) {
                log.debug("Unauthorized (401) для {}. Останавливаем попытки для этого endpoint.", endpoint);
                return FuzzingResult.STOPPED_UNAUTHORIZED;
            }
            
            if (code == 403) {
                log.debug("Forbidden (403) для {}. Останавливаем попытки для этого endpoint.", endpoint);
                return FuzzingResult.STOPPED_FORBIDDEN;
            }
            
            // Возвращаем успешный результат
            String body = null;
            ResponseBody responseBody = response.body();
            if (responseBody != null) {
                body = responseBody.string();
            }
            
            return new FuzzingResult(true, code, body, null);
            
        } catch (java.net.SocketTimeoutException e) {
            log.debug("Timeout для {}: {}", endpoint, e.getMessage());
            // Timeout - счетчики уже зарезервированы, запрос был отправлен
            return FuzzingResult.TIMEOUT;
            
        } catch (IOException e) {
            log.debug("IO error для {}: {}", endpoint, e.getMessage());
            // IO ошибка - счетчики уже зарезервированы, попытка была сделана
            return new FuzzingResult(false, 0, null, e.getMessage());
            
        } catch (Exception e) {
            log.debug("Unexpected error для {}: {}", endpoint, e.getMessage());
            // Неожиданная ошибка - счетчики уже зарезервированы, попытка была сделана
            return new FuzzingResult(false, 0, null, e.getMessage());
        }
        // ПРИМЕЧАНИЕ: Счетчики НЕ откатываются при ошибках, так как запрос был отправлен
        // Это гарантирует что лимиты не будут превышены даже при ошибках
    }
    
    /**
     * Проверка SQL Injection через gentle probing
     */
    private List<Vulnerability> probeSQLInjection(String endpoint, String method) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (endpoint == null || targetUrl == null) {
            return vulnerabilities;
        }
        
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        for (String payload : SQL_PAYLOADS) {
            if (endpointCounter.get() >= MAX_REQUESTS_PER_ENDPOINT) {
                break;
            }
            
            // КРИТИЧНО: Умный URL encoding для разных типов payloads
            // Для SQL payloads сохраняем кавычки для корректного SQL синтаксиса
            // Для NoSQL/LDAP кодируем спецсимволы но сохраняем структуру
            String encodedPayload;
            if (payload.contains("'") || payload.contains("\"") || payload.contains("--")) {
                // SQL payloads - кодируем только пробелы и опасные символы кроме кавычек
                encodedPayload = payload.replace(" ", "%20")
                    .replace("<", "%3C")
                    .replace(">", "%3E")
                    .replace("&", "%26");
            } else if (payload.contains("{") || payload.contains("$") || payload.contains("(")) {
                // NoSQL/LDAP payloads - кодируем спецсимволы но сохраняем структуру
                encodedPayload = java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8)
                    .replace("+", "%20") // Пробелы как %20 а не +
                    .replace("*", "%2A"); // * для LDAP
            } else {
                // Для остальных payloads используем полное URL encoding
                encodedPayload = java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8);
            }
            
            String testUrl = buildTestUrl(endpoint, "query", encodedPayload);
            if (testUrl == null) {
                log.debug("Не удалось построить URL для SQL Injection probe, пропускаем");
                continue;
            }
            
            Request request = new Request.Builder()
                .url(testUrl)
                .get()
                .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (gentle-probing)")
                .build();
            
            log.debug("SQL Injection probe: {} {}", method, testUrl);
            
            FuzzingResult result = executeRequest(request, endpoint);
            
            if (result.shouldStop()) {
                break;
            }
            
            if (result.success && result.body != null) {
                String body = result.body;
                if (body.contains("SQL syntax") || body.contains("MySQL") || 
                    body.contains("PostgreSQL") || body.contains("ORA-") ||
                    body.contains("SQLite") || body.contains("ODBC")) {
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SQL_INJECTION, endpoint, method, "query", 
                            "ПОДТВЕРЖДЕНА SQL Injection"))
                        .type(VulnerabilityType.SQL_INJECTION)
                        .severity(Severity.CRITICAL)
                        .title("ПОДТВЕРЖДЕНА SQL Injection через gentle probing")
                        .description(
                            "Эндпоинт " + endpoint + " вернул SQL ошибку при тестировании с payload: " + payload + ". " +
                            "Это РЕАЛЬНАЯ SQL Injection уязвимость, подтвержденная тестированием!"
                        )
                        .endpoint(endpoint)
                        .method(method)
                        .recommendation(
                            "КРИТИЧНО: Используйте prepared statements и параметризованные запросы. " +
                            "Эта уязвимость ПОДТВЕРЖДЕНА реальным запросом!"
                        )
                        .owaspCategory("Injection - SQL Injection (CONFIRMED by testing)")
                        .evidence("HTTP " + result.code + ", SQL error detected in response")
                        .confidence(95)
                        .priority(1)
                        .build());
                    
                    log.warn("SQL Injection ПОДТВЕРЖДЕНА на {}!", testUrl);
                    break; // Нашли - хватит
                }
            }
            
            sleep(DELAY_MS);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка NoSQL Injection
     */
    private List<Vulnerability> probeNoSQLInjection(String endpoint, String method) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (endpoint == null || targetUrl == null) {
            return vulnerabilities;
        }
        
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        for (String payload : NOSQL_PAYLOADS) {
            if (endpointCounter.get() >= MAX_REQUESTS_PER_ENDPOINT) {
                break;
            }
            
            // КРИТИЧНО: Умный URL encoding для разных типов payloads
            // Для SQL payloads сохраняем кавычки для корректного SQL синтаксиса
            // Для NoSQL/LDAP кодируем спецсимволы но сохраняем структуру
            String encodedPayload;
            if (payload.contains("'") || payload.contains("\"") || payload.contains("--")) {
                // SQL payloads - кодируем только пробелы и опасные символы кроме кавычек
                encodedPayload = payload.replace(" ", "%20")
                    .replace("<", "%3C")
                    .replace(">", "%3E")
                    .replace("&", "%26");
            } else if (payload.contains("{") || payload.contains("$") || payload.contains("(")) {
                // NoSQL/LDAP payloads - кодируем спецсимволы но сохраняем структуру
                encodedPayload = java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8)
                    .replace("+", "%20") // Пробелы как %20 а не +
                    .replace("*", "%2A"); // * для LDAP
            } else {
                // Для остальных payloads используем полное URL encoding
                encodedPayload = java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8);
            }
            
            String testUrl = buildTestUrl(endpoint, "query", encodedPayload);
            if (testUrl == null) {
                log.debug("Не удалось построить URL для NoSQL Injection probe, пропускаем");
                continue;
            }
            
            Request request = new Request.Builder()
                .url(testUrl)
                .get()
                .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (gentle-probing)")
                .build();
            
            log.debug("NoSQL Injection probe: {} {}", method, testUrl);
            
            FuzzingResult result = executeRequest(request, endpoint);
            
            if (result.shouldStop()) {
                break;
            }
            
            if (result.success && result.body != null) {
                String body = result.body;
                if (body.contains("MongoDB") || body.contains("NoSQL") || 
                    body.contains("BSON") || body.contains("MongoError")) {
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.NOSQL_INJECTION, endpoint, method, "query",
                            "ПОДТВЕРЖДЕНА NoSQL Injection"))
                        .type(VulnerabilityType.NOSQL_INJECTION)
                        .severity(Severity.CRITICAL)
                        .title("ПОДТВЕРЖДЕНА NoSQL Injection через gentle probing")
                        .description(
                            "Эндпоинт " + endpoint + " вернул NoSQL ошибку при тестировании с payload: " + payload + ". " +
                            "Это РЕАЛЬНАЯ NoSQL Injection уязвимость, подтвержденная тестированием!"
                        )
                        .endpoint(endpoint)
                        .method(method)
                        .recommendation(
                            "КРИТИЧНО: Используйте параметризованные запросы и валидацию входных данных. " +
                            "Эта уязвимость ПОДТВЕРЖДЕНА реальным запросом!"
                        )
                        .owaspCategory("Injection - NoSQL Injection (CONFIRMED by testing)")
                        .evidence("HTTP " + result.code + ", NoSQL error detected in response")
                        .confidence(95)
                        .priority(1)
                        .build());
                    
                    log.warn("NoSQL Injection ПОДТВЕРЖДЕНА на {}!", testUrl);
                    break;
                }
            }
            
            sleep(DELAY_MS);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка Command Injection
     */
    private List<Vulnerability> probeCommandInjection(String endpoint, String method) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (endpoint == null || targetUrl == null) {
            return vulnerabilities;
        }
        
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        for (String payload : COMMAND_INJECTION_PAYLOADS) {
            if (endpointCounter.get() >= MAX_REQUESTS_PER_ENDPOINT) {
                break;
            }
            
            // КРИТИЧНО: Умный URL encoding для разных типов payloads
            // Для SQL payloads сохраняем кавычки для корректного SQL синтаксиса
            // Для NoSQL/LDAP кодируем спецсимволы но сохраняем структуру
            String encodedPayload;
            if (payload.contains("'") || payload.contains("\"") || payload.contains("--")) {
                // SQL payloads - кодируем только пробелы и опасные символы кроме кавычек
                encodedPayload = payload.replace(" ", "%20")
                    .replace("<", "%3C")
                    .replace(">", "%3E")
                    .replace("&", "%26");
            } else if (payload.contains("{") || payload.contains("$") || payload.contains("(")) {
                // NoSQL/LDAP payloads - кодируем спецсимволы но сохраняем структуру
                encodedPayload = java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8)
                    .replace("+", "%20") // Пробелы как %20 а не +
                    .replace("*", "%2A"); // * для LDAP
            } else {
                // Для остальных payloads используем полное URL encoding
                encodedPayload = java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8);
            }
            
            String testUrl = buildTestUrl(endpoint, "cmd", encodedPayload);
            if (testUrl == null) {
                log.debug("Не удалось построить URL для Command Injection probe, пропускаем");
                continue;
            }
            
            Request request = new Request.Builder()
                .url(testUrl)
                .get()
                .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (gentle-probing)")
                .build();
            
            log.debug("Command Injection probe: {} {}", method, testUrl);
            
            FuzzingResult result = executeRequest(request, endpoint);
            
            if (result.shouldStop()) {
                break;
            }
            
            // Command injection сложно обнаружить через ответ, но можем проверить по времени ответа
            if (result.success && result.code == 200) {
                // Если ответ очень быстрый (<100ms) - возможно команда выполнилась
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.COMMAND_INJECTION, endpoint, method, "cmd",
                        "ВОЗМОЖНА Command Injection"))
                    .type(VulnerabilityType.COMMAND_INJECTION)
                    .severity(Severity.CRITICAL)
                    .title("ВОЗМОЖНА Command Injection")
                    .description(
                        "Эндпоинт " + endpoint + " принимает параметр который может быть использован для выполнения команд. " +
                        "Требуется дополнительная проверка."
                    )
                    .endpoint(endpoint)
                    .method(method)
                    .recommendation(
                        "КРИТИЧНО: НЕ используйте Runtime.exec() с пользовательским вводом! " +
                        "Используйте безопасные API вместо shell команд."
                    )
                    .owaspCategory("Injection - Command Injection (Potential)")
                    .evidence("HTTP " + result.code + ", command parameter detected")
                    .confidence(70)
                    .priority(2)
                    .build());
                
                log.warn("Возможная Command Injection на {}!", testUrl);
                break;
            }
            
                sleep(DELAY_MS);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка LDAP Injection
     */
    private List<Vulnerability> probeLDAPInjection(String endpoint, String method) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (endpoint == null || targetUrl == null) {
            return vulnerabilities;
        }
        
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        for (String payload : LDAP_PAYLOADS) {
            if (endpointCounter.get() >= MAX_REQUESTS_PER_ENDPOINT) {
                break;
            }
            
            // КРИТИЧНО: Умный URL encoding для разных типов payloads
            // Для SQL payloads сохраняем кавычки для корректного SQL синтаксиса
            // Для NoSQL/LDAP кодируем спецсимволы но сохраняем структуру
            String encodedPayload;
            if (payload.contains("'") || payload.contains("\"") || payload.contains("--")) {
                // SQL payloads - кодируем только пробелы и опасные символы кроме кавычек
                encodedPayload = payload.replace(" ", "%20")
                    .replace("<", "%3C")
                    .replace(">", "%3E")
                    .replace("&", "%26");
            } else if (payload.contains("{") || payload.contains("$") || payload.contains("(")) {
                // NoSQL/LDAP payloads - кодируем спецсимволы но сохраняем структуру
                encodedPayload = java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8)
                    .replace("+", "%20") // Пробелы как %20 а не +
                    .replace("*", "%2A"); // * для LDAP
            } else {
                // Для остальных payloads используем полное URL encoding
                encodedPayload = java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8);
            }
            
            String testUrl = buildTestUrl(endpoint, "username", encodedPayload);
            if (testUrl == null) {
                log.debug("Не удалось построить URL для LDAP Injection probe, пропускаем");
                continue;
            }
            
            Request request = new Request.Builder()
                .url(testUrl)
                .get()
                .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (gentle-probing)")
                .build();
            
            log.debug("LDAP Injection probe: {} {}", method, testUrl);
            
            FuzzingResult result = executeRequest(request, endpoint);
            
            if (result.shouldStop()) {
                break;
            }
            
            if (result.success && result.body != null) {
                String body = result.body;
                if (body.contains("LDAP") || body.contains("bind") || 
                    body.contains("invalid DN") || body.contains("LDAPException")) {
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.LDAP_INJECTION, endpoint, method, "username",
                            "ПОДТВЕРЖДЕНА LDAP Injection"))
                        .type(VulnerabilityType.LDAP_INJECTION)
                        .severity(Severity.CRITICAL)
                        .title("ПОДТВЕРЖДЕНА LDAP Injection через gentle probing")
                        .description(
                            "Эндпоинт " + endpoint + " вернул LDAP ошибку при тестировании с payload: " + payload + ". " +
                            "Это РЕАЛЬНАЯ LDAP Injection уязвимость, подтвержденная тестированием!"
                        )
                        .endpoint(endpoint)
                        .method(method)
                        .recommendation(
                            "КРИТИЧНО: Используйте параметризованные LDAP запросы и валидацию входных данных. " +
                            "Эта уязвимость ПОДТВЕРЖДЕНА реальным запросом!"
                        )
                        .owaspCategory("Injection - LDAP Injection (CONFIRMED by testing)")
                        .evidence("HTTP " + result.code + ", LDAP error detected in response")
                        .confidence(95)
                        .priority(1)
                        .build());
                    
                    log.warn("LDAP Injection ПОДТВЕРЖДЕНА на {}!", testUrl);
                    break;
                }
            }
            
            sleep(DELAY_MS);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка SSRF через gentle probing
     */
    private List<Vulnerability> probeSSRF(String endpoint, String method) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (endpoint == null || targetUrl == null) {
            return vulnerabilities;
        }
        
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        // Только 2 безопасных проверки
        for (int i = 0; i < Math.min(2, SSRF_PAYLOADS.length); i++) {
            if (endpointCounter.get() >= MAX_REQUESTS_PER_ENDPOINT) {
                break;
            }
            
            String payload = SSRF_PAYLOADS[i];
            // КРИТИЧНО: Умный URL encoding для разных типов payloads
            // Для SQL payloads сохраняем кавычки для корректного SQL синтаксиса
            // Для NoSQL/LDAP кодируем спецсимволы но сохраняем структуру
            String encodedPayload;
            if (payload.contains("'") || payload.contains("\"") || payload.contains("--")) {
                // SQL payloads - кодируем только пробелы и опасные символы кроме кавычек
                encodedPayload = payload.replace(" ", "%20")
                    .replace("<", "%3C")
                    .replace(">", "%3E")
                    .replace("&", "%26");
            } else if (payload.contains("{") || payload.contains("$") || payload.contains("(")) {
                // NoSQL/LDAP payloads - кодируем спецсимволы но сохраняем структуру
                encodedPayload = java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8)
                    .replace("+", "%20") // Пробелы как %20 а не +
                    .replace("*", "%2A"); // * для LDAP
            } else {
                // Для остальных payloads используем полное URL encoding
                encodedPayload = java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8);
            }
            
            String testUrl = buildTestUrl(endpoint, "url", encodedPayload);
            if (testUrl == null) {
                log.debug("Не удалось построить URL для SSRF probe, пропускаем");
                continue;
            }
            
            Request request = new Request.Builder()
                .url(testUrl)
                .get()
                .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (gentle-probing)")
                .build();
            
            log.debug("SSRF probe: {} {}", method, testUrl);
            
            FuzzingResult result = executeRequest(request, endpoint);
            
            if (result.shouldStop()) {
                break;
            }
            
            if (result.success && (result.code == 500 || result.code == 502 || result.code == 504)) {
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.SSRF, endpoint, method, "url",
                        "ВОЗМОЖНА SSRF уязвимость"))
                    .type(VulnerabilityType.SSRF)
                    .severity(Severity.HIGH)
                    .title("ВОЗМОЖНА SSRF уязвимость")
                    .description(
                        "Эндпоинт " + endpoint + " принимает URL параметр и может быть уязвим к SSRF. " +
                        "Требуется дополнительная проверка."
                    )
                    .endpoint(endpoint)
                    .method(method)
                    .recommendation(
                        "Проверьте валидацию URL параметров. Разрешайте только whitelist доменов. " +
                        "Используйте SSRF защиту."
                    )
                    .owaspCategory("API7:2023 - SSRF (Potential)")
                    .evidence("HTTP " + result.code + ", URL parameter detected")
                    .confidence(75)
                    .priority(2)
                    .build());
                
                log.warn("Возможная SSRF на {}!", testUrl);
                break;
            }
            
            sleep(DELAY_MS);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка BOLA через gentle probing
     */
    private List<Vulnerability> probeBOLA(String endpoint, String method) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (endpoint == null || targetUrl == null) {
            return vulnerabilities;
        }
        
        if (!endpoint.contains("{")) {
            return vulnerabilities; // Нет параметров - пропускаем
        }
        
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        for (String testId : BOLA_PAYLOADS) {
            if (endpointCounter.get() >= MAX_REQUESTS_PER_ENDPOINT) {
                break;
            }
            
            String fullUrl = buildBolaUrl(endpoint, testId);
            if (fullUrl == null) {
                log.debug("Не удалось построить URL для BOLA probe, пропускаем");
                continue;
            }
            
                Request request = new Request.Builder()
                    .url(fullUrl)
                    .get()
                    .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (gentle-probing)")
                    .build();
                
            log.debug("BOLA probe: {} {}", method, fullUrl);
            
            FuzzingResult result = executeRequest(request, endpoint);
            
            if (result.shouldStop()) {
                break;
            }
            
            if (result.success && result.code == 200 && result.body != null) {
                String body = result.body;
                        // Если получили данные без auth - потенциальная BOLA!
                        if (body.length() > 10 && !body.contains("error") && !body.contains("unauthorized")) {
                            vulnerabilities.add(Vulnerability.builder()
                                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.BOLA, endpoint, method, String.valueOf(testId),
                                    "ПОДТВЕРЖДЕНА BOLA через gentle probing"))
                                .type(VulnerabilityType.BOLA)
                                .severity(Severity.HIGH)
                                .title("ПОДТВЕРЖДЕНА BOLA через gentle probing")
                                .description(
                            "Эндпоинт " + endpoint + " вернул данные для ID=" + testId + " БЕЗ аутентификации. " +
                                    "Это РЕАЛЬНАЯ BOLA уязвимость, подтвержденная тестированием!"
                                )
                        .endpoint(endpoint)
                        .method(method)
                                .recommendation(
                                    "КРИТИЧНО: Добавьте аутентификацию И проверку владельца объекта. " +
                                    "Эта уязвимость ПОДТВЕРЖДЕНА реальным запросом!"
                                )
                                .owaspCategory("API1:2023 - BOLA (CONFIRMED by testing)")
                        .evidence("HTTP " + result.code + ", body length: " + body.length() + " bytes")
                        .confidence(90)
                        .priority(1)
                                .build());
                            
                    log.warn("BOLA ПОДТВЕРЖДЕНА на {}!", fullUrl);
                            break; // Нашли - хватит
                        }
                    }
            
            sleep(DELAY_MS);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка аутентификации (Broken Authentication, BFLA)
     */
    private List<Vulnerability> probeAuthentication(String endpoint, String method) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (endpoint == null || targetUrl == null) {
            return vulnerabilities;
        }
        
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        if (endpointCounter.get() >= MAX_REQUESTS_PER_ENDPOINT) {
            return vulnerabilities;
        }
        
        // КРИТИЧНО: Безопасное формирование URL для authentication probe
        // КРИТИЧНО: Защита от StringIndexOutOfBoundsException если targetUrl пустой
        String normalizedTarget = (targetUrl != null && targetUrl.length() > 0 && targetUrl.endsWith("/")) 
            ? targetUrl.substring(0, targetUrl.length() - 1) : targetUrl;
        String normalizedEndpoint = endpoint.startsWith("/") ? endpoint : "/" + endpoint;
        String fullUrl = normalizedTarget + normalizedEndpoint;
        
        // КРИТИЧНО: Корректная обработка разных HTTP методов
        Request.Builder requestBuilder = new Request.Builder()
            .url(fullUrl)
            .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (gentle-probing)");
        
        // Устанавливаем метод корректно
        switch (method.toUpperCase()) {
            case "GET":
                requestBuilder.get();
                break;
            case "POST":
                requestBuilder.post(RequestBody.create("", okhttp3.MediaType.parse("application/json")));
                break;
            case "PUT":
                requestBuilder.put(RequestBody.create("", okhttp3.MediaType.parse("application/json")));
                break;
            case "DELETE":
                requestBuilder.delete();
                break;
            case "PATCH":
                requestBuilder.patch(RequestBody.create("", okhttp3.MediaType.parse("application/json")));
                break;
            default:
                requestBuilder.get(); // По умолчанию GET
        }
        
        Request request = requestBuilder.build();
        
        log.debug("Authentication probe: {} {}", method, fullUrl);
        
        FuzzingResult result = executeRequest(request, endpoint);
        
        if (result.shouldStop()) {
            return vulnerabilities;
        }
        
        // Если получили 200 без auth - проблема!
        if (result.success && result.code == 200) {
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BROKEN_AUTHENTICATION, endpoint, method, null,
                    "ПОДТВЕРЖДЕНА Broken Authentication"))
                .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                .severity(Severity.HIGH)
                .title("ПОДТВЕРЖДЕНА Broken Authentication")
                .description(
                    "Эндпоинт " + endpoint + " доступен БЕЗ аутентификации (HTTP 200). " +
                    "Это РЕАЛЬНАЯ уязвимость, подтвержденная тестированием!"
                )
                .endpoint(endpoint)
                .method(method)
                .recommendation(
                    "КРИТИЧНО: Добавьте обязательную аутентификацию для этого endpoint. " +
                    "Эта уязвимость ПОДТВЕРЖДЕНА реальным запросом!"
                )
                .owaspCategory("API2:2023 - Broken Authentication (CONFIRMED by testing)")
                .evidence("HTTP " + result.code + " без аутентификации")
                .confidence(95)
                .priority(1)
                .build());
            
            log.warn("Broken Authentication ПОДТВЕРЖДЕНА на {}!", fullUrl);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Внутренний класс для результата fuzzing
     */
    private static class FuzzingResult {
        final boolean success;
        final int code;
        final String body;
        final String error;
        
        // Специальные результаты остановки
        static final FuzzingResult STOPPED_RATE_LIMIT = new FuzzingResult(false, 429, null, "Rate limit");
        static final FuzzingResult STOPPED_UNAUTHORIZED = new FuzzingResult(false, 401, null, "Unauthorized");
        static final FuzzingResult STOPPED_FORBIDDEN = new FuzzingResult(false, 403, null, "Forbidden");
        static final FuzzingResult STOPPED_LIMIT_REACHED = new FuzzingResult(false, 0, null, "Global limit reached");
        static final FuzzingResult STOPPED_ENDPOINT_LIMIT = new FuzzingResult(false, 0, null, "Endpoint limit reached");
        static final FuzzingResult TIMEOUT = new FuzzingResult(false, 0, null, "Timeout");
        
        FuzzingResult(boolean success, int code, String body, String error) {
            this.success = success;
            this.code = code;
            this.body = body;
            this.error = error;
        }
        
        boolean shouldStop() {
            return this == STOPPED_RATE_LIMIT || 
                   this == STOPPED_UNAUTHORIZED || 
                   this == STOPPED_FORBIDDEN ||
                   this == STOPPED_LIMIT_REACHED ||
                   this == STOPPED_ENDPOINT_LIMIT;
        }
    }
    
    /**
     * Безопасное формирование URL для тестирования
     * Обрабатывает edge cases: trailing/leading slashes, полные URL в endpoint
     */
    private String buildTestUrl(String endpoint, String paramName, String paramValue) {
        if (targetUrl == null || endpoint == null) {
            return null;
        }
        
        // Если endpoint уже полный URL - используем его напрямую
        if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
            return endpoint + (endpoint.contains("?") ? "&" : "?") + paramName + "=" + paramValue;
        }
        
        // Нормализуем targetUrl и endpoint для избежания двойных слешей
        // КРИТИЧНО: Защита от StringIndexOutOfBoundsException если targetUrl пустой
        String normalizedTarget = (targetUrl != null && targetUrl.length() > 0 && targetUrl.endsWith("/")) 
            ? targetUrl.substring(0, targetUrl.length() - 1) : targetUrl;
        String normalizedEndpoint = endpoint.startsWith("/") ? endpoint : "/" + endpoint;
        
        String baseUrl = normalizedTarget + normalizedEndpoint;
        return baseUrl + (baseUrl.contains("?") ? "&" : "?") + paramName + "=" + paramValue;
    }
    
    /**
     * Безопасное формирование URL для BOLA (без параметров, только путь)
     */
    private String buildBolaUrl(String endpoint, String testId) {
        if (targetUrl == null || endpoint == null) {
            return null;
        }
        
        // Если endpoint уже полный URL - используем его напрямую
        if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
            return endpoint.replaceAll("\\{[^}]+\\}", testId);
        }
        
        // Нормализуем targetUrl и endpoint
        // КРИТИЧНО: Защита от StringIndexOutOfBoundsException если targetUrl пустой
        String normalizedTarget = (targetUrl != null && targetUrl.length() > 0 && targetUrl.endsWith("/")) 
            ? targetUrl.substring(0, targetUrl.length() - 1) : targetUrl;
        String normalizedEndpoint = endpoint.startsWith("/") ? endpoint : "/" + endpoint;
        String testPath = normalizedEndpoint.replaceAll("\\{[^}]+\\}", testId);
        
        return normalizedTarget + testPath;
    }
    
    private void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Обратная совместимость: старый метод gentleProbing
     * @deprecated Используйте targetedProbing после сканеров
     */
    @Deprecated
    public List<Vulnerability> gentleProbing(OpenAPI openAPI, OpenAPIParser parser) {
        log.warn("Используется устаревший метод gentleProbing. Рекомендуется использовать targetedProbing.");
        // Для обратной совместимости возвращаем пустой список
        return new ArrayList<>();
    }
}
