package com.vtb.scanner.models;

import lombok.Data;
import lombok.Builder;

/**
 * Нарушение контракта API (несоответствие спецификации)
 */
@Data
@Builder
public class ContractViolation {
    private String endpoint;
    private String method;
    private ViolationType type;
    private String description;
    private String expected;
    private String actual;
    private Severity severity;
}

