package com.vtb.scanner.dynamic;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
public class ScenarioTrace {
    private String id;
    private String name;
    private String source;
    @Builder.Default
    private long delayMs = 150L;
    @Builder.Default
    private boolean safeGuardEnabled = true;
    @Builder.Default
    private int maxSteps = 10;
    @Builder.Default
    private List<ScenarioStep> steps = new ArrayList<>();
}
