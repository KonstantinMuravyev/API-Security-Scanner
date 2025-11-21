package com.vtb.scanner.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.core.SecurityScanner;
import com.vtb.scanner.models.ScanResult;
import com.vtb.scanner.models.Vulnerability;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Прогон сканера на реальном Virtual Bank API (https://vbank.open.bankingapi.ru/openapi.json).
 *
 * Тест предназначен для ручного запуска (требует интернет):
 *  1. Скачивает свежую спецификацию;
 *  2. Запускает SecurityScanner со всеми включенными эвристиками;
 *  3. Сохраняет полный отчёт рядом (vbank-scan-report.json);
 *  4. Проверяет, что нет очевидных ложных срабатываний (например, LDAP у account_id).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class VirtualBankApiSmokeTest {

    private static final String SPEC_URL = "https://vbank.open.bankingapi.ru/openapi.json";
    private static final Path SPEC_FILE = Path.of("build/tmp/vbank", "openapi.json");
    private static final Path REPORT_FILE = SPEC_FILE.getParent().resolve("vbank-scan-report.json");
    private static final String TARGET_URL = "https://vbank.open.bankingapi.ru";

    @BeforeAll
    void prepareSpec() throws IOException, InterruptedException {
        Files.createDirectories(SPEC_FILE.getParent());

        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(SPEC_URL))
            .timeout(Duration.ofSeconds(30))
            .GET()
            .build();

        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, response.statusCode(), "Не удалось скачать спецификацию Virtual Bank API");

        Files.write(SPEC_FILE, response.body());
        assertTrue(Files.size(SPEC_FILE) > 0, "Скачанная спецификация пустая");
    }

    @Test
    @DisplayName("VirtualBank API – полный прогон сканера без ложных критических срабатываний")
    void runFullScan() throws Exception {
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromFile(SPEC_FILE.toString());

        assertNotNull(parser.getOpenAPI(), "OpenAPI объект должен быть инициализирован");

        SecurityScanner scanner = new SecurityScanner(parser, TARGET_URL, true);

        long started = System.nanoTime();
        ScanResult result = scanner.scan();
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);

        assertNotNull(result, "ScanResult должен быть создан");
        List<Vulnerability> vulnerabilities = result.getVulnerabilities();
        assertNotNull(vulnerabilities, "Список уязвимостей не должен быть null");
        assertFalse(vulnerabilities.isEmpty(), "На реальном API должны найтись Findings (ожидаем минимум 1)");

        // Проверка, что нет прежних ложных срабатываний (LDAP на account_id и т.д.)
        List<Vulnerability> suspicious = vulnerabilities.stream()
            .filter(v -> v.getType() == com.vtb.scanner.models.VulnerabilityType.LDAP_INJECTION)
            .filter(v -> v.getEndpoint() != null && v.getEndpoint().contains("/accounts/{account_id}"))
            .collect(Collectors.toList());
        assertTrue(suspicious.isEmpty(),
            "Ожидаем, что LDAP Injection по account_id больше не срабатывает ложным образом");

        // Сохраняем полный отчёт для ручного анализа
        ObjectMapper mapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        mapper.writerWithDefaultPrettyPrinter().writeValue(REPORT_FILE.toFile(), result);

        System.out.println("=== Virtual Bank API scan summary ===");
        System.out.println("API: " + parser.getApiTitle() + " v" + parser.getApiVersion());
        System.out.println("Operations: " + parser.getAllEndpoints().size());
        System.out.println("Vulnerabilities total: " + vulnerabilities.size());
        long criticalCount = vulnerabilities.stream()
            .filter(v -> v.getSeverity() == com.vtb.scanner.models.Severity.CRITICAL)
            .count();
        long highCount = vulnerabilities.stream()
            .filter(v -> v.getSeverity() == com.vtb.scanner.models.Severity.HIGH)
            .count();
        System.out.println("Critical: " + criticalCount);
        System.out.println("High: " + highCount);
        System.out.println("Scan duration: " + elapsedMs + " ms");
        System.out.println("Report saved to: " + REPORT_FILE.toAbsolutePath());
    }
}

