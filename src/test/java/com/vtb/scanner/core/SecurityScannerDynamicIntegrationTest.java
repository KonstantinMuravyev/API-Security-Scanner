package com.vtb.scanner.core;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.vtb.scanner.dynamic.DynamicScanReport;
import com.vtb.scanner.models.ScanResult;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class SecurityScannerDynamicIntegrationTest {

    private HttpServer server;
    private String baseUrl;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/public/info", new JsonHandler());
        server.start();
        baseUrl = "http://localhost:" + server.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void scanProducesDynamicFindings() {
        OpenAPIParser parser = new OpenAPIParser();
        var resource = getClass().getClassLoader().getResource("openapi-samples/dynamic-sample.yaml");
        assertNotNull(resource, "Не найден тестовый OpenAPI: openapi-samples/dynamic-sample.yaml");
        try {
            parser.parseFromFile(Path.of(resource.toURI()).toString());
        } catch (Exception e) {
            fail("Не удалось загрузить спецификацию: " + e.getMessage());
        }

        SecurityScanner scanner = new SecurityScanner(parser, baseUrl, false);
        ScanResult result = scanner.scan();
        assertNotNull(result);
        DynamicScanReport dynamicReport = result.getDynamicScanReport();
        assertNotNull(dynamicReport);
        assertTrue(dynamicReport.hasFindings(), "Ожидались динамические находки");
        assertTrue(dynamicReport.getFindings().stream()
            .anyMatch(finding -> finding.getEndpoint().equals("/public/info")));
    }

    private static class JsonHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            byte[] body = "{\"status\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        }
    }
}
