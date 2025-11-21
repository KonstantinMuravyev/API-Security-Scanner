package com.vtb.scanner.dynamic;

import com.vtb.scanner.models.Severity;
import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Результат динамического анализа/реплея сценариев.
 */
@Data
@Builder
public class DynamicFinding {

    public enum Type {
        UNAUTHORIZED_ACCESS,
        UNEXPECTED_STATUS,
        RATE_LIMIT_ISSUE,
        LATENCY_SPIKE,
        NETWORK_ANOMALY,
        OTHER
    }

    private String id;
    private Type type;
    private Severity severity;
    private String endpoint;
    private String method;
    private String description;
    private String evidence;
    @Builder.Default
    private long durationMs = 0;
    @Builder.Default
    private List<String> relatedVulnerabilityIds = new ArrayList<>();
}
