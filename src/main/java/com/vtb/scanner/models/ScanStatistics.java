package com.vtb.scanner.models;

import lombok.Data;
import lombok.Builder;

/**
 * Статистика сканирования
 */
@Data
@Builder
public class ScanStatistics {
    private int totalEndpoints;
    private int scannedEndpoints;
    private int totalVulnerabilities;
    private int criticalVulnerabilities;
    private int highVulnerabilities;
    private int mediumVulnerabilities;
    private int lowVulnerabilities;
    private int infoVulnerabilities;
    private int contractViolations;
    private long scanDurationMs;
    
    @Builder.Default
    private boolean gostCheckEnabled = false;
}

