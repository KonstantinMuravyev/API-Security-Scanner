package com.vtb.scanner.reports;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.vtb.scanner.models.ScanResult;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Генератор отчетов в формате JSON
 */
@Slf4j
public class JsonReportGenerator implements ReportGenerator {
    
    private final ObjectMapper objectMapper;
    
    public JsonReportGenerator() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }
    
    @Override
    public void generate(ScanResult result, Path outputPath) throws IOException {
        log.info("Генерация JSON отчета: {}", outputPath);
        
        // КРИТИЧНО: Защита от NPE
        if (result == null) {
            throw new IllegalArgumentException("ScanResult не может быть null");
        }
        
        // Обеспечиваем корректную сериализацию чисел и пустых коллекций
        ScanResult sanitized = sanitizeResult(result);
        String json = objectMapper.writeValueAsString(sanitized);
        Files.writeString(outputPath, json);
        
        log.info("JSON отчет сохранен: {} ({} байт)", outputPath, Files.size(outputPath));
    }
    
    @Override
    public String getFileExtension() {
        return "json";
    }

    private ScanResult sanitizeResult(ScanResult result) {
        if (result.getExecutiveSummary() != null) {
            var summary = result.getExecutiveSummary();
            if (summary.getTopCriticalFindings() != null) {
                summary.getTopCriticalFindings().removeIf(java.util.Objects::isNull);
            }
            if (summary.getSeverityBreakdown() == null) {
                summary.setSeverityBreakdown(new java.util.LinkedHashMap<>());
            }
            if (summary.getPriorityBreakdown() == null) {
                summary.setPriorityBreakdown(new java.util.LinkedHashMap<>());
            }
        }
        if (result.getStatistics() != null) {
            var stats = result.getStatistics();
            if (Double.isNaN(stats.getAverageRiskScore()) || Double.isInfinite(stats.getAverageRiskScore())) {
                stats.setAverageRiskScore(0.0);
            }
            if (stats.getImpactSummary() != null) {
                stats.getImpactSummary().replaceAll((key, value) -> value == null ? 0L : value);
            }
        }
        return result;
    }
}

