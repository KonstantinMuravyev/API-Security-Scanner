package com.vtb.scanner.dynamic;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TelemetrySummary {
    @Builder.Default
    private int totalResponses = 0;
    @Builder.Default
    private int successResponses = 0;
    @Builder.Default
    private int unauthorizedResponses = 0;
    @Builder.Default
    private int forbiddenResponses = 0;
    @Builder.Default
    private int rateLimitResponses = 0;
    @Builder.Default
    private int serverErrors = 0;
    @Builder.Default
    private int timeouts = 0;
    @Builder.Default
    private int networkErrors = 0;
    @Builder.Default
    private long totalLatencyMs = 0;
}
