package com.vtb.scanner.models;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
public class ThreatGraph {
    @Builder.Default
    private List<ThreatNode> nodes = new ArrayList<>();
    @Builder.Default
    private List<ThreatEdge> edges = new ArrayList<>();
    @Builder.Default
    private List<ThreatPath> criticalPaths = new ArrayList<>();
    @Builder.Default
    private double maxScore = 0;
    @Builder.Default
    private double averageScore = 0;
}

