package com.vtb.scanner.reports;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.vtb.scanner.models.ScanResult;
import com.vtb.scanner.models.ExecutiveSummary;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@Slf4j
public class ExecutiveSummaryExporter {

    private final ObjectMapper mapper;

    public ExecutiveSummaryExporter() {
        this.mapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .findAndRegisterModules();
    }

    public void writeSummary(Path targetFile, ScanResult result) throws IOException {
        if (result == null) {
            throw new IllegalArgumentException("ScanResult is null");
        }
        ExecutiveSummary summary = result.getExecutiveSummary();
        if (summary == null) {
            throw new IllegalStateException("Executive summary was not computed. Ensure SecurityScanner was executed.");
        }
        Files.createDirectories(targetFile.getParent());
        mapper.writeValue(targetFile.toFile(), summary);
        log.debug("Executive summary exported to {}", targetFile.toAbsolutePath());
    }
}
