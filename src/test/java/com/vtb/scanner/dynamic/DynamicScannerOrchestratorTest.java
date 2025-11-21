package com.vtb.scanner.dynamic;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.vtb.scanner.models.AttackSurfaceSummary;
import com.vtb.scanner.models.EntryPointSummary;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DynamicScannerOrchestratorTest {

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
    void orchestratorProducesFindingsFromEntryPoint() {
        AttackSurfaceSummary summary = AttackSurfaceSummary.builder()
            .entryPointDetails(List.of(EntryPointSummary.builder()
                .key("GET /public/info")
                .method("GET")
                .path("/public/info")
                .severity("HIGH")
                .weakProtection(true)
                .riskScore(150)
                .build()))
            .build();

        DynamicScanReport report = new DynamicScannerOrchestrator()
            .execute(baseUrl, summary, null);

        assertNotNull(report);
        assertTrue(report.hasFindings(), "Ожидались динамические находки для незащищённой точки входа");
        assertTrue(report.getFindings().stream()
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
