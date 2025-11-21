package com.vtb.scanner.dynamic;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.vtb.scanner.config.ScannerConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ScenarioReplayerTest {

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
    void replaySingleStepScenario() {
        ScannerConfig.DynamicScanner config = new ScannerConfig.DynamicScanner();
        config.setEnabled(true);
        config.setDelayMs(10L);
        config.setTimeoutSec(2);
        config.setMaxScenarios(1);
        config.setMaxStepsPerScenario(2);
        config.setMaxRequestsPerSecond(2);
        DynamicScannerSettings settings = new DynamicScannerSettings(config);

        TelemetryCollector collector = new TelemetryCollector();
        ScenarioReplayer replayer = new ScenarioReplayer(settings, collector);

        ScenarioStep step = ScenarioStep.builder()
            .method("GET")
            .path("/public/info")
            .shouldEnforceAuth(true)
            .description("Check public info")
            .build();

        ScenarioTrace trace = ScenarioTrace.builder()
            .id("trace-1")
            .name("Public info trace")
            .steps(List.of(step))
            .maxSteps(1)
            .delayMs(5L)
            .build();

        ScenarioReplayResult result = replayer.replay(baseUrl, trace);
        assertNotNull(result);
        assertEquals(1, result.getStepResults().size());
        ScenarioStepResult stepResult = result.getStepResults().get(0);
        assertTrue(stepResult.isSuccess());
        assertEquals(200, stepResult.getStatusCode());
        assertNotNull(stepResult.getResponseBody());

        TelemetrySummary summary = collector.summarize();
        assertEquals(1, summary.getTotalResponses());
        assertEquals(1, summary.getSuccessResponses());
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
