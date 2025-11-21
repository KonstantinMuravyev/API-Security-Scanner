package com.vtb.scanner.dynamic;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Сводка динамического сканирования/реплея сценариев.
 */
@Data
@Builder
public class DynamicScanReport {

    @Builder.Default
    private List<DynamicFinding> findings = new ArrayList<>();

    @Builder.Default
    private List<String> anomalies = new ArrayList<>();

    @Builder.Default
    private List<String> telemetryNotices = new ArrayList<>();

    @Builder.Default
    private int executedScenarios = 0;

    @Builder.Default
    private int executedSteps = 0;

    @Builder.Default
    private int payloadBlueprints = 0;

    @Builder.Default
    private int payloadsMatched = 0;

    @Builder.Default
    private int appendedTraces = 0;

    public boolean hasFindings() {
        return findings != null && !findings.isEmpty();
    }

    public boolean hasAnomalies() {
        return anomalies != null && !anomalies.isEmpty();
    }

    public static DynamicScanReport empty() {
        return DynamicScanReport.builder().build();
    }
}
