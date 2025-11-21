package com.vtb.scanner.dynamic;

import com.vtb.scanner.models.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

class DynamicAnalyzer {

    List<DynamicFinding> analyze(ScenarioReplayResult replayResult, TelemetrySummary summary) {
        List<DynamicFinding> findings = new ArrayList<>();
        if (replayResult == null || replayResult.getStepResults() == null) {
            return findings;
        }

        for (ScenarioStepResult stepResult : replayResult.getStepResults()) {
            ScenarioStep step = stepResult.getStep();
            if (step == null) {
                continue;
            }
            int status = stepResult.getStatusCode();

            if (stepResult.isSuccess() && step.isShouldEnforceAuth() && status >= 200 && status < 300) {
                findings.add(DynamicFinding.builder()
                    .id("DYN-" + UUID.randomUUID())
                    .type(DynamicFinding.Type.UNAUTHORIZED_ACCESS)
                    .severity(Severity.HIGH)
                    .endpoint(step.getPath())
                    .method(step.getMethod())
                    .description("Эндпоинт отвечает 2xx без авторизации при динамическом доступе.")
                    .evidence("HTTP " + status)
                    .durationMs(stepResult.getDurationMs())
                    .build());
                continue;
            }

            if (step.getExpectedStatus() != null && stepResult.isSuccess() && status != step.getExpectedStatus()) {
                findings.add(DynamicFinding.builder()
                    .id("DYN-" + UUID.randomUUID())
                    .type(DynamicFinding.Type.UNEXPECTED_STATUS)
                    .severity(Severity.MEDIUM)
                    .endpoint(step.getPath())
                    .method(step.getMethod())
                    .description("Ожидался код " + step.getExpectedStatus() + ", но получен " + status + ".")
                    .evidence(stepResult.getResponseBody())
                    .durationMs(stepResult.getDurationMs())
                    .build());
            }

            if (!stepResult.isSuccess() && stepResult.getError() != null) {
                findings.add(DynamicFinding.builder()
                    .id("DYN-" + UUID.randomUUID())
                    .type(DynamicFinding.Type.NETWORK_ANOMALY)
                    .severity(Severity.MEDIUM)
                    .endpoint(step.getPath())
                    .method(step.getMethod())
                    .description("Сетевая ошибка при динамическом вызове: " + stepResult.getError())
                    .evidence(stepResult.getError())
                    .durationMs(stepResult.getDurationMs())
                    .build());
            }

            if (stepResult.isSuccess() && status >= 500) {
                findings.add(DynamicFinding.builder()
                    .id("DYN-" + UUID.randomUUID())
                    .type(DynamicFinding.Type.OTHER)
                    .severity(Severity.MEDIUM)
                    .endpoint(step.getPath())
                    .method(step.getMethod())
                    .description("Сервер вернул " + status + " при аккуратном сценарии.")
                    .evidence(stepResult.getResponseBody())
                    .durationMs(stepResult.getDurationMs())
                    .build());
            }
        }

        if (summary != null) {
            if (summary.getRateLimitResponses() == 0 && summary.getTotalResponses() > 5) {
                findings.add(DynamicFinding.builder()
                    .id("DYN-" + UUID.randomUUID())
                    .type(DynamicFinding.Type.RATE_LIMIT_ISSUE)
                    .severity(Severity.MEDIUM)
                    .endpoint("*")
                    .method("MULTI")
                    .description("Во время сценариев не получено ответов 429. Проверьте наличие rate limiting.")
                    .evidence("responses=" + summary.getTotalResponses())
                    .build());
            }
            long avgLatency = summary.getTotalResponses() > 0
                ? summary.getTotalLatencyMs() / summary.getTotalResponses()
                : 0;
            if (avgLatency > 1000) {
                findings.add(DynamicFinding.builder()
                    .id("DYN-" + UUID.randomUUID())
                    .type(DynamicFinding.Type.LATENCY_SPIKE)
                    .severity(Severity.LOW)
                    .endpoint("*")
                    .method("MULTI")
                    .description("Средняя задержка ответов выше 1 секунды: " + avgLatency + " мс")
                    .evidence("avgLatency=" + avgLatency)
                    .build());
            }
        }

        return findings;
    }
}
