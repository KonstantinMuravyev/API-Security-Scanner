package com.vtb.scanner.dynamic;

import java.util.ArrayList;
import java.util.List;

class TelemetryCollector {

    private final List<TelemetryEvent> events = new ArrayList<>();

    void recordResponse(String endpoint, int statusCode, long durationMs) {
        events.add(TelemetryEvent.builder()
            .type(TelemetryEventType.RESPONSE)
            .endpoint(endpoint)
            .statusCode(statusCode)
            .durationMs(durationMs)
            .build());
    }

    void recordTimeout(String endpoint) {
        events.add(TelemetryEvent.builder()
            .type(TelemetryEventType.TIMEOUT)
            .endpoint(endpoint)
            .detail("timeout")
            .build());
    }

    void recordNetworkError(String endpoint, String message) {
        events.add(TelemetryEvent.builder()
            .type(TelemetryEventType.NETWORK_ERROR)
            .endpoint(endpoint)
            .detail(message)
            .build());
    }

    TelemetrySummary summarize() {
        int totalResponses = 0;
        int success = 0;
        int unauthorized = 0;
        int forbidden = 0;
        int rateLimit = 0;
        int serverErrors = 0;
        int timeouts = 0;
        int networkErrors = 0;
        long totalLatency = 0;

        for (TelemetryEvent event : events) {
            switch (event.getType()) {
                case RESPONSE -> {
                    totalResponses++;
                    totalLatency += Math.max(0, event.getDurationMs());
                    int code = event.getStatusCode();
                    if (code >= 200 && code < 300) {
                        success++;
                    } else if (code == 401) {
                        unauthorized++;
                    } else if (code == 403) {
                        forbidden++;
                    } else if (code == 429) {
                        rateLimit++;
                    } else if (code >= 500) {
                        serverErrors++;
                    }
                }
                case TIMEOUT -> timeouts++;
                case NETWORK_ERROR -> networkErrors++;
            }
        }

        return TelemetrySummary.builder()
            .totalResponses(totalResponses)
            .successResponses(success)
            .unauthorizedResponses(unauthorized)
            .forbiddenResponses(forbidden)
            .rateLimitResponses(rateLimit)
            .serverErrors(serverErrors)
            .timeouts(timeouts)
            .networkErrors(networkErrors)
            .totalLatencyMs(totalLatency)
            .build();
    }

    List<String> buildNotices() {
        TelemetrySummary summary = summarize();
        List<String> notices = new ArrayList<>();
        if (summary.getTimeouts() > 0) {
            notices.add("Обнаружены таймауты при воспроизведении сценариев: " + summary.getTimeouts());
        }
        if (summary.getNetworkErrors() > 0) {
            notices.add("Сетевые ошибки при динамическом сканировании: " + summary.getNetworkErrors());
        }
        if (summary.getServerErrors() > 0) {
            notices.add("Сервер вернул " + summary.getServerErrors() + " ответов 5xx во время динамических проверок");
        }
        return notices;
    }

    List<TelemetryEvent> getEvents() {
        return events;
    }
}
