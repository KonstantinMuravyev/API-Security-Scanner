package com.vtb.scanner.dynamic;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TelemetryCollectorTest {

    @Test
    void summarizeCountsAndNotices() {
        TelemetryCollector collector = new TelemetryCollector();
        collector.recordResponse("/ok", 200, 120);
        collector.recordResponse("/auth", 401, 80);
        collector.recordResponse("/retry", 429, 50);
        collector.recordTimeout("/timeout");
        collector.recordNetworkError("/error", "connection reset");

        TelemetrySummary summary = collector.summarize();
        assertEquals(3, summary.getTotalResponses());
        assertEquals(1, summary.getSuccessResponses());
        assertEquals(1, summary.getUnauthorizedResponses());
        assertEquals(1, summary.getRateLimitResponses());
        assertEquals(1, summary.getTimeouts());
        assertEquals(1, summary.getNetworkErrors());
        assertTrue(summary.getTotalLatencyMs() > 0);

        assertFalse(collector.buildNotices().isEmpty());
    }
}
