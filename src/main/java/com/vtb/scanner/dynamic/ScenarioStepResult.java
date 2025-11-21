package com.vtb.scanner.dynamic;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ScenarioStepResult {
    private ScenarioStep step;
    private boolean success;
    private int statusCode;
    private long durationMs;
    private String responseBody;
    private String error;
}
