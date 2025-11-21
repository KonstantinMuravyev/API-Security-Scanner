package com.vtb.scanner.models;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ThreatEdge {
    private String from;
    private String to;
    private String type;
    private String label;
}

