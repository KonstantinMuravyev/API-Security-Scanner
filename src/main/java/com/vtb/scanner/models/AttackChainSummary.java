package com.vtb.scanner.models;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Краткое описание цепочки атаки для отчётов
 */
@Data
@Builder
public class AttackChainSummary {
    @Builder.Default
    private String type = "ATTACK_CHAIN";
    private String target;
    @Builder.Default
    private String severity = "UNKNOWN";
    @Builder.Default
    private boolean exploitable = false;
    private String dataSensitivityLevel;
    @Builder.Default
    private List<String> steps = new ArrayList<>();
    @Builder.Default
    private List<String> sensitiveFields = new ArrayList<>();
    @Builder.Default
    private int riskScore = 0;
    @Builder.Default
    private List<String> signals = new ArrayList<>();
    @Builder.Default
    private Map<String, String> metadata = new LinkedHashMap<>();
}

