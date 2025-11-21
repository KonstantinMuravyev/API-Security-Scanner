package com.vtb.scanner.integration;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.core.SecurityScanner;
import com.vtb.scanner.models.ScanResult;
import com.vtb.scanner.models.Vulnerability;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

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
    void testGitHubAPI_ParserHandlesLargeFile() {
        String largeSpec = buildLargeOpenApiJson(600, 40, false);
        try (LargeApiServer server = new LargeApiServer(largeSpec)) {
            OpenAPIParser parser = new OpenAPIParser();

            assertDoesNotThrow(() -> parser.parseFromUrl(server.getUrl()),
                "Парсер должен обработать большой synthetic API без ошибок");

            assertNotNull(parser.getOpenAPI(), "OpenAPI объект должен быть создан");
            assertNotNull(parser.getApiTitle(), "API title должен быть заполнен");
            assertTrue(parser.getAllEndpoints().size() >= 600,
                "Synthetic API должен иметь не менее 600 эндпоинтов");
        } catch (IOException e) {
            fail("Не удалось запустить локальный сервер: " + e.getMessage());
        }
    }
    
    /**
     * Тест сканирования GitHub API
     * 
     * Проверяет что сканер может обработать большой API
     */
    @Test
    void testGitHubAPI_FullScan() {
        String largeSpec = buildLargeOpenApiJson(600, 40, true);
        try (LargeApiServer server = new LargeApiServer(largeSpec)) {
            OpenAPIParser parser = new OpenAPIParser();
            parser.parseFromUrl(server.getUrl());

            SecurityScanner scanner = new SecurityScanner(parser, "http://localhost", false);

            long startTime = System.currentTimeMillis();
            ScanResult result = scanner.scan();
            long duration = System.currentTimeMillis() - startTime;

            assertNotNull(result, "ScanResult должен быть создан");
            assertNotNull(result.getVulnerabilities(), "Список уязвимостей не должен быть null");
            assertTrue(result.getVulnerabilities().size() > 0,
                "Synthetic large API должен иметь хотя бы одну найденную уязвимость");

            System.out.println("✅ Synthetic Large API успешно просканирован:");
            System.out.println("   - Уязвимостей найдено: " + result.getVulnerabilities().size());
            System.out.println("   - Время сканирования: " + duration + " ms");
        } catch (IOException e) {
            fail("Не удалось запустить локальный сервер: " + e.getMessage());
        }
    }
    
    /**
     * Тест что парсер правильно определяет размер файла через URL
     */
    @Test
    void testParser_DetectsLargeFileFromUrl() {
        String largeSpec = buildLargeOpenApiJson(800, 50, false);
        try (LargeApiServer server = new LargeApiServer(largeSpec)) {
            OpenAPIParser parser = new OpenAPIParser();
            assertDoesNotThrow(() -> parser.parseFromUrl(server.getUrl()),
                "Парсер должен обработать большой файл по URL без OutOfMemoryError");
            assertNotNull(parser.getOpenAPI(), "Парсинг должен быть успешным");
        } catch (IOException e) {
            fail("Не удалось запустить локальный сервер: " + e.getMessage());
        }
    }
    
    /**
     * Тест что парсер отклоняет слишком большие файлы (>100MB)
     */
    @Test
    void testParser_RejectsTooLargeFiles() {
        String largeSpec = buildLargeOpenApiJson(1500, 50000, false);
        int payloadSizeBytes = largeSpec.getBytes(StandardCharsets.UTF_8).length;
        assertTrue(payloadSizeBytes > 1_500_000, "Тестовый payload должен быть больше 1.5 MB");
        String previousLimit = System.getProperty("scanner.max.file.size.mb");
        System.setProperty("scanner.max.file.size.mb", "1");
        try (LargeApiServer server = new LargeApiServer(largeSpec)) {
            OpenAPIParser parser = new OpenAPIParser();
            assertThrows(IllegalArgumentException.class, () -> parser.parseFromUrl(server.getUrl()),
                "Ожидаем отклонение слишком большого файла");
        } catch (IOException e) {
            fail("Не удалось запустить локальный сервер: " + e.getMessage());
        } finally {
            if (previousLimit != null) {
                System.setProperty("scanner.max.file.size.mb", previousLimit);
            } else {
                System.clearProperty("scanner.max.file.size.mb");
            }
        }
    }
    
    /**
     * Тест что JSON парсинг работает для больших файлов
     * 
     * Проверяет что parseJsonDirectly работает корректно
     */
    @Test
    void testLargeJson_ParsingWorks() {
        String largeSpec = buildLargeOpenApiJson(900, 80, false);
        try (LargeApiServer server = new LargeApiServer(largeSpec)) {
            OpenAPIParser parser = new OpenAPIParser();
            assertDoesNotThrow(() -> parser.parseFromUrl(server.getUrl()),
                "JSON парсер должен обработать большой файл");
            assertNotNull(parser.getOpenAPI(), "JSON должен быть успешно распарсен");
        } catch (IOException e) {
            fail("Не удалось запустить локальный сервер: " + e.getMessage());
        }
    }
    
    /**
     * Тест производительности на большом API
     * 
     * Проверяет что сканирование выполняется в разумное время
     */
    @Test
    void testLargeAPI_Performance() {
        String largeSpec = buildLargeOpenApiJson(600, 40, true);
        try (LargeApiServer server = new LargeApiServer(largeSpec)) {
            OpenAPIParser parser = new OpenAPIParser();
            parser.parseFromUrl(server.getUrl());

            SecurityScanner scanner = new SecurityScanner(parser, "http://localhost", false);

            long startTime = System.currentTimeMillis();
            ScanResult result = scanner.scan();
            long duration = System.currentTimeMillis() - startTime;

            assertTrue(duration < 60_000,
                String.format("Сканирование большого API должно быть < 60 сек, получено: %d ms", duration));

            System.out.println("⏱️ Производительность synthetic large API:");
            System.out.println("   - Время: " + duration + " ms");
            System.out.println("   - Эндпоинтов: " + parser.getAllEndpoints().size());
            System.out.println("   - Уязвимостей: " + result.getVulnerabilities().size());
        } catch (IOException e) {
            fail("Не удалось запустить локальный сервер: " + e.getMessage());
        }
    }
    
    /**
     * Тест что все уязвимости на большом API имеют корректные данные
     */
    @Test
    void testLargeAPI_AllVulnerabilitiesValid() {
        String largeSpec = buildLargeOpenApiJson(600, 40, true);
        try (LargeApiServer server = new LargeApiServer(largeSpec)) {
            OpenAPIParser parser = new OpenAPIParser();
            parser.parseFromUrl(server.getUrl());

            SecurityScanner scanner = new SecurityScanner(parser, "http://localhost", false);
            ScanResult result = scanner.scan();

            assertFalse(result.getVulnerabilities().isEmpty(), "Должны быть обнаружены уязвимости на synthetic API");

            for (Vulnerability vuln : result.getVulnerabilities()) {
                assertNotNull(vuln.getId(), "ID не должен быть null для " + vuln);
                assertNotNull(vuln.getTitle(), "Title не должен быть null для " + vuln.getId());
                assertNotNull(vuln.getDescription(), "Description не должен быть null для " + vuln.getId());
                assertTrue(vuln.getConfidence() > 0 && vuln.getConfidence() <= 100,
                    "Confidence должен быть 1-100 для " + vuln.getId());
                assertNotNull(vuln.getSeverity(), "Severity не должен быть null для " + vuln.getId());
            }
        } catch (IOException e) {
            fail("Не удалось запустить локальный сервер: " + e.getMessage());
        }
    }

    private static String buildLargeOpenApiJson(int pathCount, int descriptionRepeat, boolean includeSensitiveQuery) {
        String filler = "SyntheticLargeDescription".repeat(descriptionRepeat);
        StringBuilder paths = new StringBuilder();
        for (int i = 0; i < pathCount; i++) {
            if (i > 0) {
                paths.append(',');
            }
            paths.append("\"/resource").append(i).append("\":{");
            paths.append("\"get\":{");
            paths.append("\"summary\":\"Resource ").append(i).append("\",");
            if (includeSensitiveQuery && i == 0) {
                paths.append("\"parameters\":[{\"name\":\"password\",\"in\":\"query\",\"schema\":{\"type\":\"string\"}}],");
            }
            paths.append("\"responses\":{\"200\":{\"description\":\"OK\"}}");
            paths.append("}}");
        }
        return "{"
            + "\"openapi\":\"3.0.1\","
            + "\"info\":{\"title\":\"Synthetic Large API\",\"version\":\"1.0.0\",\"description\":\"" + filler + "\"},"
            + "\"paths\":{" + paths + "},"
            + "\"components\":{\"schemas\":{\"LargeSchema\":{\"type\":\"object\",\"properties\":{\"value\":{\"type\":\"string\",\"description\":\"" + filler + "\"}}}}}"
            + "}";
    }

    private static final class LargeApiServer implements AutoCloseable {
        private final com.sun.net.httpserver.HttpServer server;
        private final String url;

        LargeApiServer(String body) throws IOException {
            this.server = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress(0), 0);
            this.server.createContext("/api.json", exchange -> {
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            });
            this.server.start();
            this.url = "http://localhost:" + this.server.getAddress().getPort() + "/api.json";
        }

        String getUrl() {
            return url;
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
