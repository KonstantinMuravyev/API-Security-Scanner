package com.vtb.scanner.dynamic;

import lombok.Builder;
import lombok.Data;

import java.util.LinkedHashMap;
import java.util.Map;

@Data
@Builder
public class ScenarioStep {
    private String method;
    private String path;
    @Builder.Default
    private Map<String, String> headers = new LinkedHashMap<>();
    private String body;
    private Integer expectedStatus;
    @Builder.Default
    private boolean shouldEnforceAuth = false;
    @Builder.Default
    private boolean allowRedirects = false;
    private String description;
}
