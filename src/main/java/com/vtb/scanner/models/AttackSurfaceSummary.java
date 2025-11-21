package com.vtb.scanner.models;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Сводка карты поверхности атаки для HTML/JSON отчётов
 */
@Data
@Builder
public class AttackSurfaceSummary {
    @Builder.Default
    private String context = "GENERAL";
    @Builder.Default
    private int totalEndpoints = 0;
    @Builder.Default
    private int relationshipCount = 0;
    @Builder.Default
    private int entryPointCount = 0;
    @Builder.Default
    private int exploitableChains = 0;
    @Builder.Default
    private List<String> entryPoints = new ArrayList<>();
    @Builder.Default
    private List<EntryPointSummary> entryPointDetails = new ArrayList<>();
    @Builder.Default
    private int maxEntryPointRisk = 0;
    @Builder.Default
    private double averageEntryPointRisk = 0;
    @Builder.Default
    private List<AttackChainSummary> attackChains = new ArrayList<>();
    @Builder.Default
    private Map<String, Long> chainsBySeverity = new LinkedHashMap<>();
}

