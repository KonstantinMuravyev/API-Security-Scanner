package com.vtb.scanner.dynamic;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TelemetryEvent {
    private TelemetryEventType type;
    private String endpoint;
    private int statusCode;
    private long durationMs;
    private String detail;
}
