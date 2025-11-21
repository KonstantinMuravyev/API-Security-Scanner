package com.vtb.scanner.models;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Data
@Builder
public class DataProtectionSummary {
    @Builder.Default
    private int totalSignals = 0;
    @Builder.Default
    private int criticalExposures = 0;
    @Builder.Default
    private int unauthorizedFlows = 0;
    @Builder.Default
    private int consentGapCount = 0;
    @Builder.Default
    private boolean insecureTransportDetected = false;
    @Builder.Default
    private boolean consentMissingDetected = false;
    @Builder.Default
    private boolean storageExposureDetected = false;
    @Builder.Default
    private boolean loggingExposureDetected = false;
    @Builder.Default
    private List<PiiExposure> exposures = new ArrayList<>();
    @Builder.Default
    private List<String> highRiskChains = new ArrayList<>();
    @Builder.Default
    private Set<String> recommendedActions = new LinkedHashSet<>();
}

