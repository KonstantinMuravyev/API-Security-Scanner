package com.vtb.scanner.models;

import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Data
@Builder
public class PiiExposure {
    private String endpoint;
    private String method;
    @Builder.Default
    private Severity severity = Severity.MEDIUM;
    @Builder.Default
    private Set<String> signals = new LinkedHashSet<>();
    @Builder.Default
    private List<String> vulnerabilityIds = new ArrayList<>();
    @Builder.Default
    private boolean unauthorizedAccess = false;
    @Builder.Default
    private boolean consentMissing = false;
    @Builder.Default
    private boolean insecureTransport = false;
}

