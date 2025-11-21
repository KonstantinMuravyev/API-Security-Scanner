package com.vtb.scanner.models;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
public class ThreatPath {
    private String name;
    private Severity severity;
    @Builder.Default
    private double score = 0;
    @Builder.Default
    private List<String> nodeIds = new ArrayList<>();
    @Builder.Default
    private List<String> steps = new ArrayList<>();
    private String description;
}

