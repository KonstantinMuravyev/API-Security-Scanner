package com.vtb.scanner.dynamic;

import com.vtb.scanner.models.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DynamicAnalyzerTest {

    @Test
    void detectsUnauthorizedAccess() {
        ScenarioStep step = ScenarioStep.builder()
            .method("GET")
            .path("/public/info")
            .shouldEnforceAuth(true)
            .expectedStatus(401)
            .build();

        ScenarioStepResult stepResult = ScenarioStepResult.builder()
            .step(step)
            .success(true)
            .statusCode(200)
            .durationMs(50)
            .responseBody("{\"status\":\"ok\"}")
            .build();

        ScenarioReplayResult replayResult = ScenarioReplayResult.builder()
            .trace(ScenarioTrace.builder().id("trace").steps(List.of(step)).build())
            .stepResults(List.of(stepResult))
            .build();

        TelemetrySummary summary = TelemetrySummary.builder()
            .totalResponses(1)
            .successResponses(1)
            .totalLatencyMs(50)
            .build();

        DynamicAnalyzer analyzer = new DynamicAnalyzer();
        List<DynamicFinding> findings = analyzer.analyze(replayResult, summary);
        assertFalse(findings.isEmpty());
        assertEquals(DynamicFinding.Type.UNAUTHORIZED_ACCESS, findings.get(0).getType());
        assertEquals(Severity.HIGH, findings.get(0).getSeverity());
    }

    @Test
    void addsRateLimitFindingWhenMissing429() {
        ScenarioReplayResult replayResult = ScenarioReplayResult.builder()
            .trace(ScenarioTrace.builder().id("trace").steps(List.of()).build())
            .stepResults(List.of())
            .build();

        TelemetrySummary summary = TelemetrySummary.builder()
            .totalResponses(10)
            .successResponses(10)
            .totalLatencyMs(500)
            .rateLimitResponses(0)
            .build();

        DynamicAnalyzer analyzer = new DynamicAnalyzer();
        List<DynamicFinding> findings = analyzer.analyze(replayResult, summary);
        assertTrue(findings.stream().anyMatch(f -> f.getType() == DynamicFinding.Type.RATE_LIMIT_ISSUE));
    }
}
