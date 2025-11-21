package com.vtb.scanner.dynamic;

import com.vtb.scanner.config.ScannerConfig;

class DynamicScannerSettings {
    private final ScannerConfig.DynamicScanner config;

    DynamicScannerSettings(ScannerConfig.DynamicScanner config) {
        this.config = config;
    }

    boolean isEnabled() {
        return config != null && config.isEnabled();
    }

    int maxScenarios() {
        return config != null ? config.getMaxScenarios() : 0;
    }

    int maxStepsPerScenario() {
        return config != null ? config.getMaxStepsPerScenario() : 0;
    }

    long delayMs() {
        return config != null ? config.getDelayMs() : 150L;
    }

    int timeoutSec() {
        return config != null ? config.getTimeoutSec() : 4;
    }

    int maxRequestsPerSecond() {
        return config != null ? config.getMaxRequestsPerSecond() : 1;
    }
}
