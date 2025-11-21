package com.vtb.scanner.dynamic;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
public class ScenarioReplayResult {
    private ScenarioTrace trace;
    @Builder.Default
    private List<ScenarioStepResult> stepResults = new ArrayList<>();

    public boolean hasFailures() {
        return stepResults.stream().anyMatch(result -> !result.isSuccess());
    }
}
