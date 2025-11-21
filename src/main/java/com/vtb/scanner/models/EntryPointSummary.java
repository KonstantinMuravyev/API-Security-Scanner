package com.vtb.scanner.models;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Подробная информация о точке входа (endpoint) с повышенным риском.
 */
@Data
@Builder
public class EntryPointSummary {
    private String key;
    private String method;
    private String path;
    @Builder.Default
    private String severity = "UNKNOWN";
    @Builder.Default
    private int riskScore = 0;
    @Builder.Default
    private boolean requiresAuth = false;
    @Builder.Default
    private boolean strongAuth = false;
    @Builder.Default
    private boolean consentRequired = false;
    @Builder.Default
    private boolean openBanking = false;
    private String dataSensitivityLevel;
    @Builder.Default
    private boolean weakProtection = false;
    @Builder.Default
    private boolean highRisk = false;
    @Builder.Default
    private List<String> signals = new ArrayList<>();
    @Builder.Default
    private List<String> sensitiveFields = new ArrayList<>();
    @Builder.Default
    private List<String> ssrfParameters = new ArrayList<>();
    @Builder.Default
    private List<String> injectionParameters = new ArrayList<>();
    @Builder.Default
    private List<String> privilegeParameters = new ArrayList<>();
}

