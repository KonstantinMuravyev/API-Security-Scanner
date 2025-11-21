package com.vtb.scanner.models;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class ThreatNode {
    private String id;
    private String type;
    private String label;
    @Builder.Default
    private Severity severity = Severity.INFO;
    @Builder.Default
    private double score = 0;
    @Builder.Default
    private List<String> signals = new ArrayList<>();
    @Builder.Default
    private Map<String, String> metadata = new LinkedHashMap<>();
}

