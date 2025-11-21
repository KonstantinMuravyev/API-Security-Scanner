package com.vtb.scanner.heuristics;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.parser.OpenAPIV3Parser;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SmartAnalyzerProtocolsTest {

    @Test
    void graphQlGrpcWebSocketHaveElevatedRisk() {
        OpenAPI openAPI = new OpenAPIV3Parser()
            .readLocation("src/test/resources/openapi-samples/protocols-sample.yaml", null, null)
            .getOpenAPI();
        assertNotNull(openAPI);

        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem item = entry.getValue();
            if (item.getPost() != null) {
                assertRiskHigh(path, "POST", item.getPost(), openAPI);
            }
            if (item.getGet() != null) {
                assertRiskHigh(path, "GET", item.getGet(), openAPI);
            }
        }
    }

    private void assertRiskHigh(String path, String method, Operation operation, OpenAPI openAPI) {
        int score = SmartAnalyzer.calculateRiskScore(path, method, operation, openAPI);
        assertTrue(score >= 100, "Risk score для " + path + " должен быть повышен, но равен " + score);
    }
}
