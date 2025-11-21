package com.vtb.scanner.dynamic.payload;

import lombok.Builder;
import lombok.Data;

import java.util.LinkedHashMap;
import java.util.Map;

@Data
@Builder
public class PayloadBlueprint {
    private String id;
    private PayloadType type;
    private String method;
    private String path;
    private String body;
    @Builder.Default
    private Map<String, String> headers = new LinkedHashMap<>();
    private Integer expectedStatus;
    @Builder.Default
    private boolean enforceAuth = false;
    private String description;
}

