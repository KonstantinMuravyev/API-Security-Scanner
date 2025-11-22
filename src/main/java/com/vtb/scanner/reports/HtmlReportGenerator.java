package com.vtb.scanner.reports;

import com.vtb.scanner.benchmark.BenchmarkComparator;
import com.vtb.scanner.models.AttackChainSummary;
import com.vtb.scanner.models.AttackSurfaceSummary;
import com.vtb.scanner.models.ContractViolation;
import com.vtb.scanner.models.EntryPointSummary;
import com.vtb.scanner.models.ScanResult;
import com.vtb.scanner.models.ScanStatistics;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.ThreatGraph;
import com.vtb.scanner.models.ThreatPath;
import com.vtb.scanner.models.ThreatNode;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.semantic.ContextAnalyzer;
import lombok.extern.slf4j.Slf4j;
import com.vtb.scanner.models.DataProtectionSummary;
import com.vtb.scanner.models.PiiExposure;
import com.vtb.scanner.models.ExecutiveSummary;
import com.vtb.scanner.dynamic.DynamicFinding;
import com.vtb.scanner.dynamic.DynamicScanReport;
import com.vtb.scanner.benchmark.BenchmarkComparator;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.DecimalFormat;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Генератор красивых HTML отчетов
 */
@Slf4j
public class HtmlReportGenerator implements ReportGenerator {
    
    private static final DateTimeFormatter DATE_FORMATTER = 
        DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss");
    private static final Pattern SCHEMA_GUARD_PATTERN =
        Pattern.compile("(?i)schema\\s+guard[:\\s]+([^.;\\n]+)");
    
    @Override
    public void generate(ScanResult result, Path outputPath) throws IOException {
        log.info("Генерация HTML отчета: {}", outputPath);
        
        // КРИТИЧНО: Защита от NPE
        if (result == null) {
            throw new IllegalArgumentException("ScanResult не может быть null");
        }
        
        String html = generateHtml(result);
        Files.writeString(outputPath, html);
        
        log.info("HTML отчет сохранен: {} ({} байт)", outputPath, Files.size(outputPath));
    }
    
    private String generateHtml(ScanResult result) {
        // КРИТИЧНО: Защита от NPE
        if (result == null) {
            return "<html><body><h1>Ошибка: Результат сканирования отсутствует</h1></body></html>";
        }
        
        StringBuilder html = new StringBuilder();
        ScanStatistics stats = result.getStatistics() != null ? result.getStatistics() : ScanStatistics.builder().build();
        
        String contextBadge = buildContextBadge(result.getApiContext());
        String healthBadge = buildHealthBadge(result.getApiHealthScore());
        
        html.append("""
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>API Security Scan Report - %s</title>
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body { 
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                        background: #f5f7fa;
                        padding: 20px;
                        color: #2c3e50;
                    }
                    .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
                    .header { 
                        background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
                        color: white; 
                        padding: 40px; 
                        border-radius: 12px 12px 0 0;
                    }
                    .header h1 { font-size: 32px; margin-bottom: 10px; }
                    .header p { opacity: 0.9; font-size: 16px; }
                    .stats { 
                        display: grid; 
                        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
                        gap: 20px; 
                        padding: 30px; 
                        border-bottom: 1px solid #ecf0f1;
                    }
                    .summary-section { padding: 30px; background: #ffffff; border-bottom: 1px solid #ecf0f1; }
                    .summary-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; }
                    .summary-header h2 { font-size: 26px; color: #2c3e50; }
                    .risk-badge { display: inline-flex; align-items: center; gap: 10px; padding: 8px 16px; border-radius: 999px; font-weight: 600; font-size: 14px; text-transform: uppercase; color: white; }
                    .risk-badge.CRITICAL { background: #c0392b; }
                    .risk-badge.HIGH { background: #d35400; }
                    .risk-badge.ELEVATED { background: #f39c12; color: #2c3e50; }
                    .risk-badge.MODERATE { background: #2980b9; }
                    .risk-badge.LOW { background: #27ae60; }
                    .risk-badge.UNKNOWN { background: #7f8c8d; }
                    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 18px; }
                    .summary-card { background: #f7f9fc; border-radius: 12px; padding: 18px; border: 1px solid rgba(99, 110, 255, 0.18); box-shadow: 0 3px 12px rgba(99,110,255,0.08); }
                    .summary-card .label { font-size: 13px; text-transform: uppercase; letter-spacing: 0.4px; color: #5c6bc0; margin-bottom: 6px; }
                    .summary-card .value { font-size: 28px; font-weight: 700; color: #2c3e50; }
                    .summary-card .sub { font-size: 12px; color: #7f8c8d; margin-top: 6px; }
                    .heatmap { display: grid; grid-template-columns: repeat(5, minmax(60px, 1fr)); gap: 6px; margin-top: 18px; }
                    .heatmap-cell { border-radius: 10px; padding: 14px 10px; text-align: center; font-weight: 700; color: white; }
                    .heatmap-cell.CRITICAL { background: linear-gradient(145deg, #c0392b, #e74c3c); }
                    .heatmap-cell.HIGH { background: linear-gradient(145deg, #d35400, #e67e22); }
                    .heatmap-cell.MEDIUM { background: linear-gradient(145deg, #f39c12, #f1c40f); color: #2c3e50; }
                    .heatmap-cell.LOW { background: linear-gradient(145deg, #2980b9, #3498db); }
                    .heatmap-cell.INFO { background: linear-gradient(145deg, #7f8c8d, #95a5a6); }
                    .summary-findings { margin-top: 18px; padding-left: 18px; color: #2c3e50; }
                    .summary-findings li { margin-bottom: 6px; }
                    .stat-card { text-align: center; padding: 20px; background: #f8f9fa; border-radius: 8px; }
                    .stat-number { font-size: 36px; font-weight: bold; margin-bottom: 5px; }
                    .stat-label { color: #7f8c8d; font-size: 14px; text-transform: uppercase; }
                    .critical { color: #e74c3c; }
                    .high { color: #e67e22; }
                    .medium { color: #f39c12; }
                    .low { color: #3498db; }
                    .info { color: #95a5a6; }
                    .vulnerabilities { padding: 30px; }
                    .vuln-card { 
                        border-left: 4px solid; 
                        margin-bottom: 20px; 
                        padding: 20px; 
                        background: #fafafa;
                        border-radius: 4px;
                    }
                    .vuln-card.CRITICAL { border-color: #e74c3c; }
                    .vuln-card.HIGH { border-color: #e67e22; }
                    .vuln-card.MEDIUM { border-color: #f39c12; }
                    .vuln-card.LOW { border-color: #3498db; }
                    .vuln-card.INFO { border-color: #95a5a6; }
                    .vuln-title { font-size: 18px; font-weight: 600; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
                    .vuln-badge { 
                        padding: 4px 12px; 
                        border-radius: 4px; 
                        font-size: 12px; 
                        font-weight: 600; 
                        color: white;
                    }
                    .impact-summary { padding: 10px 30px 30px; }
                    .impact-chip {
                        display: inline-flex;
                        align-items: center;
                        gap: 6px;
                        margin: 6px 8px 0 0;
                        padding: 6px 14px;
                        border-radius: 16px;
                        font-size: 13px;
                        font-weight: 600;
                        letter-spacing: 0.2px;
                        text-transform: uppercase;
                        border: 1px solid transparent;
                    }
                    .impact-chip.CRITICAL { background: #fdecea; color: #c0392b; border-color: rgba(231, 76, 60, 0.35); }
                    .impact-chip.HIGH { background: #fff3e0; color: #d35400; border-color: rgba(230, 126, 34, 0.35); }
                    .impact-chip.MEDIUM { background: #fff8e1; color: #f39c12; border-color: rgba(243, 156, 18, 0.35); }
                    .impact-chip.LOW { background: #e3f2fd; color: #1976d2; border-color: rgba(52, 152, 219, 0.35); }
                    .impact-chip.INFO { background: #f4f6f8; color: #607d8b; border-color: rgba(189, 195, 199, 0.35); }
                    .vuln-meta { color: #7f8c8d; font-size: 14px; margin-bottom: 10px; }
                    .vuln-description { margin-bottom: 10px; line-height: 1.6; }
                    .vuln-recommendation { 
                        background: #e8f5e9; 
                        padding: 12px; 
                        border-radius: 4px; 
                        margin-top: 10px;
                        border-left: 3px solid #4caf50;
                    }
                    .vuln-recommendation strong { color: #2e7d32; }
                    .gost-badge { 
                        background: #2196F3; 
                        color: white; 
                        padding: 2px 8px; 
                        border-radius: 3px; 
                        font-size: 11px; 
                        margin-left: 8px;
                    }
                    .vuln-flags { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
                    .schema-badge {
                        background: #ede7f6;
                        color: #5e35b1;
                        padding: 4px 10px;
                        border-radius: 999px;
                        font-size: 11px;
                        font-weight: 600;
                        letter-spacing: 0.3px;
                    }
                    .dynamic-badge {
                        background: #e8f5e9;
                        color: #2e7d32;
                        padding: 4px 10px;
                        border-radius: 999px;
                        font-size: 11px;
                        font-weight: 600;
                        letter-spacing: 0.3px;
                    }
                    .dynamic-badge.pending {
                        background: #fff8e1;
                        color: #ef6c00;
                    }
                    .schema-guard-list {
                        list-style: disc inside;
                        margin: 6px 0 10px 0;
                        color: #5e35b1;
                        font-size: 13px;
                    }
                    .footer { padding: 20px; text-align: center; color: #7f8c8d; font-size: 14px; border-top: 1px solid #ecf0f1; }
                    .filters-section { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
                    .filter-btn { transition: all 0.3s; }
                    .filter-btn:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.2); }
                    .filter-btn.active { box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.3); }
                    .scanner-section { margin-bottom: 25px; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden; transition: box-shadow 0.3s; }
                    .scanner-section:hover { box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
                    .scanner-header { transition: background 0.3s; }
                    .scanner-header:hover { background: linear-gradient(135deg, #764ba2 0%%, #667eea 100%%) !important; }
                    .scanner-content { transition: max-height 0.3s ease-out; }
                    .section-toggle { transition: transform 0.3s; }
                    .section-toggle.open { transform: rotate(180deg); }
                    .vuln-card.hidden { display: none !important; }
                    .top-critical-card.hidden { display: none !important; }
                    .attack-surface-section { padding: 30px; background: #fdfdfd; border-top: 1px solid #ecf0f1; }
                    .attack-surface-section h2 { font-size: 24px; margin-bottom: 15px; }
                    .attack-surface-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 18px; margin: 20px 0; }
                    .attack-surface-card { background: #fafafa; border-radius: 10px; padding: 18px; border: 1px solid #dee3f3; box-shadow: 0 2px 8px rgba(0,0,0,0.04); }
                    .attack-surface-card .label { color: #6c7a89; font-size: 13px; text-transform: uppercase; letter-spacing: 0.4px; margin-bottom: 6px; }
                    .attack-surface-card .value { font-size: 28px; font-weight: 700; color: #2c3e50; }
                    .attack-surface-card .sub { font-size: 13px; color: #7f8c8d; margin-top: 4px; }
                    .severity-chip { display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; border-radius: 999px; font-size: 12px; font-weight: 600; color: white; margin: 4px 8px 4px 0; text-transform: uppercase; }
                    .severity-chip.CRITICAL { background: #e74c3c; }
                    .severity-chip.HIGH { background: #e67e22; }
                    .severity-chip.MEDIUM { background: #f39c12; color: #2c3e50; }
                    .severity-chip.LOW { background: #3498db; }
                    .severity-chip.UNKNOWN { background: #95a5a6; }
                    .attack-entry-pills { display: flex; flex-wrap: wrap; gap: 10px; margin: 15px 0; }
                    .entry-pill { background: #eef2ff; color: #3f51b5; padding: 6px 14px; border-radius: 20px; font-size: 13px; border: 1px solid rgba(63,81,181,0.2); }
                    .attack-chain-card { border-left: 4px solid #764ba2; padding: 20px; background: white; border-radius: 10px; box-shadow: 0 3px 12px rgba(0,0,0,0.08); margin-bottom: 18px; }
                    .attack-chain-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; font-size: 15px; font-weight: 600; color: #2c3e50; }
                    .attack-chain-type { color: #764ba2; text-transform: uppercase; letter-spacing: 0.5px; font-size: 12px; }
                    .severity-badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; color: white; }
                    .severity-badge.CRITICAL { background: #e74c3c; }
                    .severity-badge.HIGH { background: #e67e22; }
                    .severity-badge.MEDIUM { background: #f39c12; color: #2c3e50; }
                    .severity-badge.LOW { background: #3498db; }
                    .severity-badge.UNKNOWN { background: #95a5a6; }
                    .attack-chain-body { color: #34495e; font-size: 14px; line-height: 1.6; }
                    .attack-chain-body ul { margin: 10px 0 0 18px; }
                    .attack-chain-body li { margin-bottom: 6px; }
                    .chain-meta { margin-top: 12px; display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; font-size: 12px; color: #555; }
                    .chain-meta span { display: block; background: #f5f7fb; padding: 8px 10px; border-radius: 6px; border: 1px solid rgba(118, 75, 162, 0.15); }
                    .sensitivity-badge { display: inline-flex; align-items: center; gap: 6px; margin-top: 10px; padding: 5px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; background: rgba(231, 76, 60, 0.1); color: #c0392b; }
                    .threat-graph-section { padding: 30px; background: #f6f7ff; border-top: 1px solid #ecf0f1; }
                    .threat-graph-section h2 { font-size: 24px; margin-bottom: 15px; }
                    .threat-stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 18px; margin: 20px 0; }
                    .threat-card { background: white; border-radius: 10px; padding: 18px; border: 1px solid #dee3f3; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
                    .threat-card h3 { font-size: 14px; text-transform: uppercase; letter-spacing: 0.3px; color: #6c7a89; margin-bottom: 8px; }
                    .threat-card .value { font-size: 28px; font-weight: 700; color: #2c3e50; }
                    .threat-card .sub { font-size: 13px; color: #7f8c8d; }
                    .path-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-top: 18px; }
                    .path-card { background: white; border-radius: 10px; border: 1px solid rgba(118, 75, 162, 0.2); padding: 18px; box-shadow: 0 2px 10px rgba(118, 75, 162, 0.08); }
                    .path-card h3 { font-size: 16px; margin-bottom: 8px; color: #2c3e50; }
                    .path-steps { font-size: 13px; color: #555; margin-top: 10px; line-height: 1.5; }
                    .path-meta { display: flex; gap: 10px; margin-top: 12px; font-size: 12px; color: #764ba2; }
                    .node-list { display: flex; flex-direction: column; gap: 12px; margin-top: 20px; }
                    .node-card { background: white; border-radius: 10px; padding: 14px 16px; border: 1px solid rgba(0,0,0,0.08); box-shadow: 0 1px 6px rgba(0,0,0,0.05); display: flex; justify-content: space-between; align-items: center; }
                    .node-info { display: flex; flex-direction: column; }
                    .node-type { text-transform: uppercase; font-size: 12px; color: #764ba2; letter-spacing: 0.4px; }
                    .node-label { font-size: 15px; font-weight: 600; color: #2c3e50; margin-top: 4px; }
                    .node-signals { font-size: 12px; color: #7f8c8d; margin-top: 6px; }
                    .node-score { font-size: 14px; font-weight: 600; color: #2c3e50; }
                    .data-protection-section { padding: 30px; background: #ffffff; border-top: 1px solid #ecf0f1; }
                    .data-protection-section h2 { font-size: 24px; margin-bottom: 12px; }
                    .dpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 18px; margin: 18px 0; }
                    .dpi-card { background: #f8f9ff; border-radius: 12px; padding: 18px; border: 1px solid rgba(102,126,234,0.2); box-shadow: 0 3px 10px rgba(102,126,234,0.08); }
                    .dpi-card h3 { font-size: 14px; text-transform: uppercase; letter-spacing: 0.3px; color: #5c6bc0; margin-bottom: 8px; }
                    .dpi-card .value { font-size: 28px; font-weight: 700; color: #2c3e50; }
                    .dpi-card .sub { font-size: 13px; color: #7f8c8d; margin-top: 4px; }
                    .pii-list { display: flex; flex-direction: column; gap: 12px; margin-top: 20px; }
                    .pii-item { border-left: 4px solid #5c6bc0; background: #fdfdff; border-radius: 10px; padding: 16px 18px; box-shadow: 0 2px 8px rgba(92,107,192,0.15); }
                    .pii-item h3 { margin-bottom: 6px; font-size: 16px; color: #2c3e50; }
                    .pii-tags { display: flex; flex-wrap: wrap; gap: 8px; margin: 8px 0; }
                    .pii-tag { background: #eef2ff; color: #3f51b5; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
                    .pii-meta { font-size: 13px; color: #566573; margin-top: 4px; }
                    .recommendations-list { margin-top: 18px; padding-left: 18px; color: #34495e; }
                    .recommendations-list li { margin-bottom: 6px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>API Security Scan Report</h1>
                        <p>API: <strong>%s</strong> v%s</p>
                        <p>Дата сканирования: %s</p>
                        <p>URL: %s</p>
                        %s
                        %s
                    </div>
            """.formatted(
                result.getApiName(),
                result.getApiName(),
                result.getApiVersion(),
                result.getScanTimestamp().format(DATE_FORMATTER),
                result.getTargetUrl(),
                contextBadge,
                healthBadge
            ));
        
        // Benchmark comparison
        BenchmarkComparator.BenchmarkComparison benchmark = BenchmarkComparator.compare(result);
        
        html.append("""
                    <div style="padding: 20px; background: #f0f8ff; border-radius: 8px; margin: 20px 0;">
                        <h3 style="margin-bottom: 15px;">Security Score</h3>
                        <div style="font-size: 48px; font-weight: bold; color: %s; margin: 10px 0;">
                            %d/100
                        </div>
                        <div style="font-size: 18px; margin: 10px 0;">
                            %s
                        </div>
                        <div style="margin-top: 15px; font-size: 14px; color: #555;">
                            <div>Плотность уязвимостей: %.2f/endpoint (industry avg: %.2f) - %s</div>
                            <div>Best Practice Score: %d/100 - %s</div>
                            <div>ГОСТ Compliance: %d/100 - %s</div>
                        </div>
                    </div>
            """.formatted(
                benchmark.getOverallSecurityScore() >= 80 ? "#27ae60" : 
                benchmark.getOverallSecurityScore() >= 60 ? "#f39c12" : "#e74c3c",
                benchmark.getOverallSecurityScore(),
                benchmark.getOverallRating(),
                benchmark.getVulnsPerEndpoint(),
                benchmark.getIndustryAvgVulnsPerEndpoint(),
                benchmark.getVulnsDensity(),
                benchmark.getBestPracticeScore(),
                benchmark.getBestPracticeLevel(),
                benchmark.getGostComplianceScore(),
                benchmark.getGostComplianceLevel()
            ));
        
        html.append(renderExecutiveSummary(result));
        
        // Статистика
        html.append("""
                    <div class="stats">
                        <div class="stat-card">
                            <div class="stat-number critical">%d</div>
                            <div class="stat-label">Critical</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number high">%d</div>
                            <div class="stat-label">High</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number medium">%d</div>
                            <div class="stat-label">Medium</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number low">%d</div>
                            <div class="stat-label">Low</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number info">%d</div>
                            <div class="stat-label">Info</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">%d</div>
                            <div class="stat-label">Max Risk Score</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">%s</div>
                            <div class="stat-label">Avg Risk Score</div>
                        </div>
                    <div class="stat-card">
                        <div class="stat-number">%d</div>
                        <div class="stat-label">Contract Violations</div>
                        </div>
                    </div>
            """.formatted(
                result.getVulnerabilityCountBySeverity(Severity.CRITICAL),
                result.getVulnerabilityCountBySeverity(Severity.HIGH),
                result.getVulnerabilityCountBySeverity(Severity.MEDIUM),
                result.getVulnerabilityCountBySeverity(Severity.LOW),
                result.getVulnerabilityCountBySeverity(Severity.INFO),
                stats.getMaxRiskScore(),
                formatDouble(stats.getAverageRiskScore()),
                stats.getContractViolations()
            ));
        html.append(renderImpactSummary(stats.getImpactSummary()));
        html.append(renderContractViolations(result));
        html.append(renderTrendSection(result));
        html.append(renderAttackSurfaceSection(result.getAttackSurface()));
        html.append(renderThreatGraphSection(result.getThreatGraph()));
        html.append(renderDataProtectionSection(result.getDataProtection()));
        html.append(renderSchemaGuardSection(result.getVulnerabilities()));
        html.append(renderDynamicSection(result));
        
        // Фильтры и уязвимости
        html.append("<div class=\"vulnerabilities\">\n");
        html.append("<h2 style=\"margin-bottom: 20px;\">Обнаруженные уязвимости</h2>\n");
        
        if (result.getVulnerabilities().isEmpty()) {
            html.append("<p style=\"color: #27ae60; font-size: 18px;\">Уязвимостей не обнаружено!</p>\n");
        } else {
            Map<String, List<DynamicFinding>> dynamicFindingMap = buildDynamicFindingMap(result.getDynamicScanReport());
            // КРИТИЧНО: Топ самых страшных уязвимостей (без дублирования)
            String context = result.getExecutiveSummary() != null ? result.getExecutiveSummary().getApiContext() : null;
            List<Vulnerability> scaryVulns = ReportInsights.getTopCriticalVulnerabilities(result.getVulnerabilities(), context);
            
            if (!scaryVulns.isEmpty()) {
                html.append("""
                    <div class="top-critical-section" style="background: linear-gradient(135deg, #e74c3c 0%%, #c0392b 100%%); padding: 25px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 12px rgba(231, 76, 60, 0.3);">
                        <h2 style="color: white; margin-bottom: 20px; font-size: 24px; font-weight: 600;">
                            Топ критичных уязвимостей
                        </h2>
                        <p style="color: rgba(255,255,255,0.9); margin-bottom: 20px; font-size: 14px;">
                            Найдено <strong id="top-critical-count">%d</strong> критичных уязвимостей требующих немедленного внимания
                        </p>
                        <div id="top-critical-list">
                """.formatted(scaryVulns.size()));
                
                // Показываем топ-10 самых критичных
                int displayCount = Math.min(10, scaryVulns.size());
                for (int i = 0; i < displayCount; i++) {
                    Vulnerability vuln = scaryVulns.get(i);
                    html.append(generateTopCriticalCard(vuln, i + 1, dynamicFindingMap));
                }
                
                html.append("</div></div>\n");
            }
            
            // Группируем по OWASP категориям (сканерам)
            Map<String, List<Vulnerability>> byCategory = result.getVulnerabilities().stream()
                .collect(Collectors.groupingBy(
                    v -> v.getOwaspCategory() != null && !v.getOwaspCategory().isEmpty() 
                        ? v.getOwaspCategory() 
                        : "Другое"
                ));
            
            // Подсчитываем статистику по приоритетам
            long priority1 = result.getVulnerabilities().stream().filter(v -> v.getPriority() == 1).count();
            long priority2 = result.getVulnerabilities().stream().filter(v -> v.getPriority() == 2).count();
            long priority3 = result.getVulnerabilities().stream().filter(v -> v.getPriority() == 3).count();
            long priority4 = result.getVulnerabilities().stream().filter(v -> v.getPriority() == 4).count();
            long priority5 = result.getVulnerabilities().stream().filter(v -> v.getPriority() == 5).count();
            int totalVulns = result.getVulnerabilities().size();
            long severityCriticalCount = result.getVulnerabilityCountBySeverity(Severity.CRITICAL);
            long severityHighCount = result.getVulnerabilityCountBySeverity(Severity.HIGH);
            long severityMediumCount = result.getVulnerabilityCountBySeverity(Severity.MEDIUM);
            long severityLowCount = result.getVulnerabilityCountBySeverity(Severity.LOW);
            long severityInfoCount = result.getVulnerabilityCountBySeverity(Severity.INFO);
            
            // Фильтры
            html.append("""
                <div class="filters-section" style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px;">
                    <h3 style="margin-bottom: 15px; color: #2c3e50;">Фильтры</h3>
                    <div style="display: flex; flex-wrap: wrap; gap: 15px; align-items: center;">
                        <div>
                            <label style="font-weight: 600; margin-right: 10px; color: #555;">По приоритету:</label>
                            <button class="filter-btn active" data-filter="priority" data-value="all" style="background: #667eea; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; font-size: 14px; margin-right: 5px;">Все <span class="filter-count" data-filter-count="priority-all">(%d)</span></button>
                            <button class="filter-btn" data-filter="priority" data-value="1" style="background: #e74c3c; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; font-size: 14px; margin-right: 5px;">P1 <span class="filter-count" data-filter-count="priority-1">(%d)</span></button>
                            <button class="filter-btn" data-filter="priority" data-value="2" style="background: #e67e22; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; font-size: 14px; margin-right: 5px;">P2 <span class="filter-count" data-filter-count="priority-2">(%d)</span></button>
                            <button class="filter-btn" data-filter="priority" data-value="3" style="background: #f39c12; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; font-size: 14px; margin-right: 5px;">P3 <span class="filter-count" data-filter-count="priority-3">(%d)</span></button>
                            <button class="filter-btn" data-filter="priority" data-value="4" style="background: #3498db; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; font-size: 14px; margin-right: 5px;">P4 <span class="filter-count" data-filter-count="priority-4">(%d)</span></button>
                            <button class="filter-btn" data-filter="priority" data-value="5" style="background: #95a5a6; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; font-size: 14px;">P5 <span class="filter-count" data-filter-count="priority-5">(%d)</span></button>
                        </div>
                        <div style="margin-top: 10px;">
                            <label style="font-weight: 600; margin-right: 10px; color: #555;">По критичности:</label>
                            <button class="filter-btn active" data-filter="severity" data-value="all" style="background: #667eea; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; font-size: 14px; margin-right: 5px;">Все <span class="filter-count" data-filter-count="severity-all">(%d)</span></button>
                            <button class="filter-btn" data-filter="severity" data-value="CRITICAL" style="background: #e74c3c; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; font-size: 14px; margin-right: 5px;">Critical <span class="filter-count" data-filter-count="severity-CRITICAL">(%d)</span></button>
                            <button class="filter-btn" data-filter="severity" data-value="HIGH" style="background: #e67e22; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; font-size: 14px; margin-right: 5px;">High <span class="filter-count" data-filter-count="severity-HIGH">(%d)</span></button>
                            <button class="filter-btn" data-filter="severity" data-value="MEDIUM" style="background: #f39c12; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; font-size: 14px; margin-right: 5px;">Medium <span class="filter-count" data-filter-count="severity-MEDIUM">(%d)</span></button>
                            <button class="filter-btn" data-filter="severity" data-value="LOW" style="background: #3498db; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; font-size: 14px; margin-right: 5px;">Low <span class="filter-count" data-filter-count="severity-LOW">(%d)</span></button>
                            <button class="filter-btn" data-filter="severity" data-value="INFO" style="background: #95a5a6; color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; font-size: 14px;">Info <span class="filter-count" data-filter-count="severity-INFO">(%d)</span></button>
                        </div>
                    </div>
                </div>
            """.formatted(
                totalVulns,
                priority1, priority2, priority3, priority4, priority5,
                totalVulns,
                severityCriticalCount, severityHighCount, severityMediumCount, severityLowCount, severityInfoCount
            ));
            
            // Группированные секции по сканерам
            html.append("<div id=\"vulnerabilities-container\">\n");
            
            int categoryIndex = 0;
            for (Map.Entry<String, List<Vulnerability>> categoryEntry : byCategory.entrySet()) {
                String category = categoryEntry.getKey();
                List<Vulnerability> vulns = categoryEntry.getValue();
                
                // Сортируем по приоритету и severity
                vulns.sort((a, b) -> {
                    int priorityCompare = Integer.compare(a.getPriority(), b.getPriority());
                    if (priorityCompare != 0) return priorityCompare;
                    return b.getSeverity().compareTo(a.getSeverity());
                });
                
                html.append(String.format("""
                    <div class="scanner-section" data-category="%s" style="margin-bottom: 25px; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
                        <div class="scanner-header" style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 15px 20px; cursor: pointer; display: flex; justify-content: space-between; align-items: center;" onclick="toggleSection(%d)">
                            <div>
                                <h3 style="margin: 0; font-size: 18px; font-weight: 600;">%s</h3>
                                <div style="font-size: 14px; opacity: 0.9; margin-top: 5px;">
                                    Найдено: <strong>%d</strong> уязвимостей
                                    <span style="margin-left: 15px;">P1: %d</span>
                                    <span style="margin-left: 10px;">P2: %d</span>
                                    <span style="margin-left: 10px;">P3: %d</span>
                                </div>
                            </div>
                            <div class="section-toggle" style="font-size: 24px; transition: transform 0.3s;">▼</div>
                        </div>
                        <div class="scanner-content" id="section-%d" style="display: none; padding: 20px; background: #fafafa;">
                """,
                    category.replaceAll("[^a-zA-Z0-9]", ""),
                    categoryIndex,
                    category,
                    vulns.size(),
                    vulns.stream().filter(v -> v.getPriority() == 1).count(),
                    vulns.stream().filter(v -> v.getPriority() == 2).count(),
                    vulns.stream().filter(v -> v.getPriority() == 3).count(),
                    categoryIndex
                ));
                
                for (Vulnerability vuln : vulns) {
                    html.append(generateVulnerabilityCard(vuln, categoryIndex, dynamicFindingMap));
                }
                
                html.append("</div></div>\n");
                categoryIndex++;
            }
            
            html.append("</div>\n");
        }
        
        html.append("</div>\n");
        
        // Footer
        html.append("""
                <div class="footer">
                    <p>Сгенерировано VTB API Security Scanner v1.0.0</p>
                    <p>Время сканирования: %d мс | Всего эндпоинтов: %d</p>
                    <p style="margin-top: 10px;">
                        <strong>Уникальные фичи:</strong> 
                        100%% OWASP Top 10 | ГОСТ TLS проверка | Attack Surface Mapping
                    </p>
                </div>
            </div>
            
            <!-- Chart.js для графиков -->
            <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
            <script>
                // График распределения по severity
                const ctx = document.createElement('canvas');
                document.querySelector('.stats').after(ctx);
                
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                        datasets: [{
                            data: [%d, %d, %d, %d, %d],
                            backgroundColor: ['#e74c3c', '#e67e22', '#f39c12', '#3498db', '#95a5a6']
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Распределение уязвимостей по критичности'
                            }
                        }
                    }
                });
                
                // Глобальные переменные для фильтров
                let currentPriorityFilter = 'all';
                let currentSeverityFilter = 'all';
                
                // Функция для переключения секций (глобальная для onclick)
                window.toggleSection = function(index) {
                    const content = document.getElementById('section-' + index);
                    if (!content) return;
                    
                    const header = content.previousElementSibling;
                    const toggle = header ? header.querySelector('.section-toggle') : null;
                    
                    if (content.style.display === 'none' || !content.style.display) {
                        content.style.display = 'block';
                        if (toggle) toggle.classList.add('open');
                    } else {
                        content.style.display = 'none';
                        if (toggle) toggle.classList.remove('open');
                    }
                };
                
                // Функция фильтрации (глобальная)
                window.applyFilters = function() {
                    document.querySelectorAll('.vuln-card').forEach(card => {
                        const priority = card.dataset.priority;
                        const severity = card.dataset.severity;
                        
                        let show = true;
                        
                        if (currentPriorityFilter !== 'all' && priority !== currentPriorityFilter) {
                            show = false;
                        }
                        
                        if (currentSeverityFilter !== 'all' && severity !== currentSeverityFilter) {
                            show = false;
                        }
                        
                        if (show) {
                            card.classList.remove('hidden');
                        } else {
                            card.classList.add('hidden');
                        }
                    });
                    
                    // Показываем/скрываем пустые секции
                    document.querySelectorAll('.scanner-section').forEach(section => {
                        const visibleCards = section.querySelectorAll('.vuln-card:not(.hidden)');
                        if (visibleCards.length === 0) {
                            section.style.display = 'none';
                        } else {
                            section.style.display = 'block';
                        }
                    });
                };
                
                // Инициализация фильтров и событий
                document.addEventListener('DOMContentLoaded', function() {
                    // Устанавливаем активные кнопки по умолчанию
                    document.querySelectorAll('.filter-btn[data-value="all"]').forEach(btn => {
                        btn.classList.add('active');
                    });
                    
                    // Назначаем обработчики кликов на кнопки фильтров
                    document.querySelectorAll('.filter-btn').forEach(btn => {
                        btn.addEventListener('click', function(e) {
                            e.preventDefault();
                            e.stopPropagation();
                            
                            const filter = this.dataset.filter;
                            const value = this.dataset.value;
                            
                            // Обновляем активную кнопку в группе
                            const group = this.closest('div');
                            if (group) {
                                group.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                            }
                            this.classList.add('active');
                            
                            // Обновляем текущий фильтр
                            if (filter === 'priority') {
                                currentPriorityFilter = value;
                            } else if (filter === 'severity') {
                                currentSeverityFilter = value;
                            }
                            
                            // Применяем фильтры
                            applyFilters();
                        });
                    });
                    
                    // Автоматически раскрываем секции с критичными уязвимостями
                    document.querySelectorAll('.scanner-section').forEach((section, index) => {
                        const criticalCount = section.querySelectorAll('.vuln-card.CRITICAL').length;
                        const highCount = section.querySelectorAll('.vuln-card.HIGH').length;
                        if (criticalCount > 0 || highCount > 0) {
                            toggleSection(index);
                        }
                    });
                });
            </script>
        </body>
        </html>
            """.formatted(
                stats.getScanDurationMs(),
                stats.getTotalEndpoints(),
                result.getVulnerabilityCountBySeverity(Severity.CRITICAL),
                result.getVulnerabilityCountBySeverity(Severity.HIGH),
                result.getVulnerabilityCountBySeverity(Severity.MEDIUM),
                result.getVulnerabilityCountBySeverity(Severity.LOW),
                result.getVulnerabilityCountBySeverity(Severity.INFO)
            ));
        
        return html.toString();
    }
    
    /**
     * Генерация карточки для топа критичных уязвимостей
     */
    private String generateTopCriticalCard(Vulnerability vuln,
                                           int rank,
                                           Map<String, List<DynamicFinding>> dynamicFindingMap) {
        StringBuilder card = new StringBuilder();
        
        String severityColor = vuln.getSeverity() == Severity.CRITICAL ? "#e74c3c" : "#e67e22";
        String severityText = vuln.getSeverity() == Severity.CRITICAL ? "CRITICAL" : "HIGH";
        String severityName = vuln.getSeverity().name();
        int priorityValue = vuln.getPriority();
        boolean dynamicVerified = hasDynamicVerification(vuln, dynamicFindingMap);
        List<String> schemaGuards = extractSchemaGuards(vuln);
        
        card.append(String.format("""
            <div class="top-critical-card %s" data-severity="%s" data-priority="%d" style="background: white; border-left: 5px solid %s; padding: 20px; margin-bottom: 15px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 10px;">
                    <div style="flex: 1;">
                        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                            <span style="background: %s; color: white; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px;">#%d</span>
                            <span style="background: %s; color: white; padding: 4px 10px; border-radius: 4px; font-weight: 600; font-size: 12px;">%s</span>
                        </div>
                        <h3 style="margin: 0; font-size: 18px; font-weight: 600; color: #2c3e50;">%s</h3>
                    </div>
                </div>
                <div style="color: #555; font-size: 14px; margin-bottom: 8px;">
                    <strong>Эндпоинт:</strong> <code style="background: #f5f5f5; padding: 2px 6px; border-radius: 3px;">%s [%s]</code>
                    <span style="margin-left: 10px; background: #eef2ff; padding: 2px 10px; border-radius: 12px; font-size: 12px; color: #3f51b5;">Risk Score: %d</span>
                </div>
                %s
                <div style="color: #555; font-size: 14px; margin-bottom: 10px; line-height: 1.5;">
                    %s
                </div>
                %s
                %s
                <div style="background: #fff3cd; padding: 10px; border-radius: 4px; border-left: 3px solid #ffc107; font-size: 13px; color: #856404;">
                    <strong>Рекомендация:</strong> %s
                </div>
            </div>
        """,
            severityName,
            severityName,
            priorityValue,
            severityColor,
            severityColor,
            rank,
            severityColor,
            severityText,
            vuln.getTitle(),
            vuln.getEndpoint(),
            vuln.getMethod(),
            vuln.getRiskScore(),
            buildFlagRow(dynamicVerified, !schemaGuards.isEmpty()),
            vuln.getDescription(),
            buildImpactBlock(vuln.getImpactLevel()),
            buildEvidenceBlock(vuln.getEvidence()) + buildSchemaGuardList(schemaGuards),
            vuln.getRecommendation() != null ? truncate(vuln.getRecommendation(), 280) : "Требуется немедленное исправление"
        ));
        
        return card.toString();
    }

    private String buildFlagRow(boolean dynamicVerified, boolean hasSchemaGuard) {
        if (!dynamicVerified && !hasSchemaGuard) {
            return "";
        }
        StringBuilder row = new StringBuilder();
        if (dynamicVerified) {
            row.append("<span class=\"dynamic-badge verified\">Dynamic verified</span>");
        }
        if (hasSchemaGuard) {
            row.append("<span class=\"schema-badge\">Schema Guard</span>");
        }
        return row.toString();
    }

    private String buildSchemaGuardList(List<String> guards) {
        if (guards == null || guards.isEmpty()) {
            return "";
        }
        StringBuilder list = new StringBuilder("<ul class=\"schema-guard-list\">");
        int displayed = 0;
        for (String guard : guards) {
            if (guard == null || guard.isBlank()) {
                continue;
            }
            list.append("<li>").append(escapeHtml(guard)).append("</li>");
            displayed++;
            if (displayed >= 3) {
                break;
            }
        }
        if (guards.size() > displayed) {
            list.append("<li>…</li>");
        }
        list.append("</ul>");
        return list.toString();
    }

    private List<String> extractSchemaGuards(Vulnerability vuln) {
        if (vuln == null || vuln.getEvidence() == null) {
            return Collections.emptyList();
        }
        Matcher matcher = SCHEMA_GUARD_PATTERN.matcher(vuln.getEvidence());
        LinkedHashSet<String> guards = new LinkedHashSet<>();
        while (matcher.find()) {
            String block = matcher.group(1);
            if (block == null) {
                continue;
            }
            String[] parts = block.split("[;,]");
            for (String part : parts) {
                String trimmed = part.trim();
                if (!trimmed.isEmpty()) {
                    guards.add(trimmed);
                }
            }
        }
        return new ArrayList<>(guards);
    }

    private int countSchemaGuardVulns(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities == null) {
            return 0;
        }
        int count = 0;
        for (Vulnerability vuln : vulnerabilities) {
            if (vuln == null) {
                continue;
            }
            if (!extractSchemaGuards(vuln).isEmpty()) {
                count++;
            }
        }
        return count;
    }

    private Map<String, List<DynamicFinding>> buildDynamicFindingMap(DynamicScanReport report) {
        Map<String, List<DynamicFinding>> map = new HashMap<>();
        if (report == null || report.getFindings() == null) {
            return map;
        }
        for (DynamicFinding finding : report.getFindings()) {
            if (finding == null) {
                continue;
            }
            if (finding.getRelatedVulnerabilityIds() != null && !finding.getRelatedVulnerabilityIds().isEmpty()) {
                for (String vulnId : finding.getRelatedVulnerabilityIds()) {
                    if (vulnId == null || vulnId.isBlank()) {
                        continue;
                    }
                    map.computeIfAbsent(vulnId, k -> new ArrayList<>()).add(finding);
                }
            } else {
                String key = buildDynamicKey(finding.getMethod(), finding.getEndpoint());
                if (key == null) {
                    continue;
                }
                map.computeIfAbsent(key, k -> new ArrayList<>()).add(finding);
            }
        }
        return map;
    }

    private boolean hasDynamicVerification(Vulnerability vuln,
                                           Map<String, List<DynamicFinding>> dynamicFindingMap) {
        if (vuln == null || dynamicFindingMap == null || dynamicFindingMap.isEmpty()) {
            return false;
        }
        if (vuln.getId() != null) {
            List<DynamicFinding> direct = dynamicFindingMap.get(vuln.getId());
            if (direct != null && !direct.isEmpty()) {
                return true;
            }
        }
        String key = buildDynamicKey(vuln.getMethod(), vuln.getEndpoint());
        if (key == null) {
            return false;
        }
        List<DynamicFinding> findings = dynamicFindingMap.get(key);
        return findings != null && !findings.isEmpty();
    }

    private String buildDynamicKey(String method, String endpoint) {
        String normalizedEndpoint = normalizeEndpointForKey(endpoint);
        if (normalizedEndpoint == null) {
            return null;
        }
        String normalizedMethod = method != null ? method.toUpperCase(Locale.ROOT) : "GET";
        return normalizedMethod + " " + normalizedEndpoint;
    }

    private String normalizeEndpointForKey(String endpoint) {
        if (endpoint == null) {
            return null;
        }
        String trimmed = endpoint.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            try {
                URI uri = URI.create(trimmed);
                if (uri.getPath() != null && !uri.getPath().isBlank()) {
                    trimmed = uri.getPath();
                }
            } catch (IllegalArgumentException ignored) {
                // fallback to original trimmed path
            }
        }
        if (!trimmed.startsWith("/")) {
            trimmed = "/" + trimmed.replaceFirst("^\\./", "");
        }
        return trimmed.replaceAll("/{2,}", "/");
    }

    private String renderAttackSurfaceSection(AttackSurfaceSummary summary) {
        if (summary == null) {
            return "";
        }
        boolean hasChains = summary.getAttackChains() != null && !summary.getAttackChains().isEmpty();
        boolean hasEntryPoints = summary.getEntryPointCount() > 0;
        if (!hasChains && !hasEntryPoints) {
            return "";
        }

        StringBuilder block = new StringBuilder();
        block.append("<section class=\"attack-surface-section\">\n");
        block.append("<h2>Attack Surface Map</h2>\n");
        block.append("<p style=\"margin-top: 10px; color: #455a64;\">Комплексный обзор поверхности атаки и потенциальных цепочек эксплуатации.</p>\n");

        block.append("<div class=\"attack-surface-grid\">\n");
        String entryPointCount = String.valueOf(summary.getEntryPointCount());
        String maxEntryRisk = summary.getEntryPointCount() > 0
            ? String.valueOf(summary.getMaxEntryPointRisk())
            : "—";
        String avgEntryRisk = summary.getEntryPointCount() > 0
            ? formatDouble(summary.getAverageEntryPointRisk())
            : "—";
        block.append(buildAttackSurfaceCard("Всего эндпоинтов", String.valueOf(summary.getTotalEndpoints()), "учтено в графе"))
            .append(buildAttackSurfaceCard("Точки входа", entryPointCount, "слабая защита/высокий риск"))
            .append(buildAttackSurfaceCard("Связи", String.valueOf(summary.getRelationshipCount()), "LIST → RESOURCE и др."))
            .append(buildAttackSurfaceCard("Эксплуатируемые цепочки", String.valueOf(summary.getExploitableChains()), "безспорная эксплуатация"))
            .append(buildAttackSurfaceCard("Max risk (entry)", maxEntryRisk, "SmartAnalyzer score"))
            .append(buildAttackSurfaceCard("Avg risk (entry)", avgEntryRisk, "по выделенным точкам"));
        block.append("</div>\n");

        if (summary.getChainsBySeverity() != null && !summary.getChainsBySeverity().isEmpty()) {
            block.append("<div style=\"margin: 12px 0;\">");
            summary.getChainsBySeverity().forEach((severity, count) ->
                block.append(buildAttackSurfaceSeverityChip(severity, count)));
            block.append("</div>");
        }

        List<EntryPointSummary> entryDetails = summary.getEntryPointDetails() != null
            ? new ArrayList<>(summary.getEntryPointDetails())
            : Collections.emptyList();
        if (!entryDetails.isEmpty()) {
            entryDetails.sort(Comparator.comparingInt(EntryPointSummary::getRiskScore).reversed());
            block.append("<h3 style=\"margin-top: 18px; font-size: 18px;\">Точки входа высокого риска</h3>")
                .append("<div class=\"attack-chain-list\">");
            int limit = Math.min(6, entryDetails.size());
            for (int i = 0; i < limit; i++) {
                block.append(renderEntryPointCard(entryDetails.get(i)));
            }
            block.append("</div>");
            if (entryDetails.size() > limit) {
                block.append("<div style=\"margin-top: 10px; color:#7f8c8d; font-size: 13px;\">Показаны первые ")
                    .append(limit)
                    .append(" из ")
                    .append(entryDetails.size())
                    .append(" обнаруженных точек входа</div>");
            }
        }

        if (hasChains) {
            block.append("<div style=\"margin-top: 25px;\">")
                .append("<h3 style=\"font-size: 18px; margin-bottom: 12px;\">Критичные цепочки атак</h3>");
            List<AttackChainSummary> chains = summary.getAttackChains();
            int limit = Math.min(10, chains.size());
            for (int i = 0; i < limit; i++) {
                block.append(renderAttackChainCard(chains.get(i), i + 1));
            }
            if (chains.size() > limit) {
                block.append("<div style=\"margin-top: 10px; color:#7f8c8d; font-size: 13px;\">Показаны первые ")
                    .append(limit)
                    .append(" из ")
                    .append(chains.size())
                    .append(" обнаруженных цепочек</div>");
            }
            block.append("</div>");
        }

        block.append("</section>\n");
        return block.toString();
    }

    private String renderThreatGraphSection(ThreatGraph graph) {
        if (graph == null || graph.getNodes() == null || graph.getNodes().isEmpty()) {
            return "";
        }

        int nodeCount = graph.getNodes().size();
        int edgeCount = graph.getEdges() != null ? graph.getEdges().size() : 0;
        int pathCount = graph.getCriticalPaths() != null ? graph.getCriticalPaths().size() : 0;
        String avgScore = formatDouble(graph.getAverageScore());
        String maxScore = formatDouble(graph.getMaxScore());

        List<ThreatPath> topPaths = new ArrayList<>(graph.getCriticalPaths() != null ? graph.getCriticalPaths() : Collections.emptyList());
        topPaths.sort(Comparator.comparingDouble(ThreatPath::getScore).reversed());
        if (topPaths.size() > 3) {
            topPaths = topPaths.subList(0, 3);
        }

        List<ThreatNode> topNodes = graph.getNodes().stream()
            .filter(node -> node != null && node.getType() != null && !"VULNERABILITY".equalsIgnoreCase(node.getType()))
            .sorted(Comparator.comparingDouble(ThreatNode::getScore).reversed())
            .limit(5)
            .collect(Collectors.toList());

        StringBuilder section = new StringBuilder();
        section.append("<section class=\"threat-graph-section\">\n");
        section.append("<h2>Threat Graph Insights</h2>\n");
        section.append("<p style=\"margin-top: 10px; color: #455a64;\">Связываем сигналы всех сканеров, чтобы выделить наиболее опасные цепочки атаки и критические узлы.</p>\n");

        section.append("<div class=\"threat-stats-grid\">\n");
        section.append(threatStatCard("Узлы", String.valueOf(nodeCount), "endpoints, entry points, attack chains"));
        section.append(threatStatCard("Связи", String.valueOf(edgeCount), "корреляция событий и сигналов"));
        section.append(threatStatCard("Критические цепочки", String.valueOf(pathCount), "отфильтрованные по риску"));
        section.append(threatStatCard("Макс. риск", maxScore, "по итогам оценки графа"));
        section.append(threatStatCard("Средний риск", avgScore, "агрегированный по узлам"));
        section.append("</div>\n");

        if (!topPaths.isEmpty()) {
            section.append("<h3 style=\"font-size:18px; margin-top:10px; color:#2c3e50;\">Приоритетные цепочки атаки</h3>\n");
            section.append("<div class=\"path-grid\">\n");
            for (ThreatPath path : topPaths) {
                String severity = path.getSeverity() != null ? path.getSeverity().name() : "UNKNOWN";
                section.append("<div class=\"path-card\">\n");
                section.append("<div style=\"display:flex; justify-content:space-between; align-items:center;\">");
                section.append("<h3>" + escapeHtml(path.getName()) + "</h3>");
                section.append("<span class=\"severity-chip " + severity + "\">" + severity + "</span>");
                section.append("</div>\n");
                section.append("<p style=\"color:#764ba2; font-weight:600; margin-top:4px;\">Score: " + formatDouble(path.getScore()) + "</p>\n");
                section.append("<p class=\"path-steps\">" + (path.getDescription() != null ? escapeHtml(path.getDescription()) : "") + "</p>\n");
                if (path.getSteps() != null && !path.getSteps().isEmpty()) {
                    section.append("<div class=\"path-meta\">\n");
                    section.append("<span>" + escapeHtml(String.join(" → ", path.getSteps())) + "</span>\n");
                    section.append("</div>\n");
                }
                section.append("</div>\n");
            }
            section.append("</div>\n");
        }

        if (!topNodes.isEmpty()) {
            section.append("<h3 style=\"font-size:18px; margin-top:22px; color:#2c3e50;\">Ключевые узлы риска</h3>\n");
            section.append("<div class=\"node-list\">\n");
            for (ThreatNode node : topNodes) {
                String nodeSeverity = node.getSeverity() != null ? node.getSeverity().name() : "INFO";
                section.append("<div class=\"node-card\">\n");
                section.append("<div class=\"node-info\">\n");
                section.append("<span class=\"node-type\">" + escapeHtml(node.getType()) + "</span>\n");
                section.append("<span class=\"node-label\">" + escapeHtml(node.getLabel()) + "</span>\n");
                section.append("<span class=\"node-signals\">Сигналы: " + (node.getSignals() != null ? node.getSignals().size() : 0) + ", Severity: <span class=\"severity-chip " + nodeSeverity + "\">" + nodeSeverity + "</span></span>\n");
                section.append("</div>\n");
                section.append("<div class=\"node-score\">Score: " + formatDouble(node.getScore()) + "</div>\n");
                section.append("</div>\n");
            }
            section.append("</div>\n");
        }

        section.append("</section>\n");
        return section.toString();
    }

    private String threatStatCard(String title, String value, String subtitle) {
        return "<div class=\"threat-card\">"
            + "<h3>" + escapeHtml(title) + "</h3>"
            + "<div class=\"value\">" + escapeHtml(value) + "</div>"
            + "<div class=\"sub\">" + escapeHtml(subtitle) + "</div>"
            + "</div>";
    }

    private String buildAttackSurfaceCard(String label, String value, String subtext) {
        StringBuilder builder = new StringBuilder("<div class=\"attack-surface-card\">");
        builder.append("<div class=\"label\">").append(escapeHtml(label)).append("</div>")
            .append("<div class=\"value\">").append(escapeHtml(value)).append("</div>");
        if (subtext != null && !subtext.isBlank()) {
            builder.append("<div class=\"sub\">").append(escapeHtml(subtext)).append("</div>");
        }
        builder.append("</div>");
        return builder.toString();
    }

    private String translateContext(String context) {
        if (context == null || context.isBlank()) {
            return ContextAnalyzer.APIContext.GENERAL.getDescription();
        }
        try {
            return ContextAnalyzer.APIContext.valueOf(context).getDescription();
        } catch (IllegalArgumentException ignored) {
            return context.toUpperCase(Locale.ROOT);
        }
    }

    private String buildAttackSurfaceSeverityChip(String severity, long count) {
        String normalized = severity != null ? severity.toUpperCase(Locale.ROOT) : "UNKNOWN";
        return "<span class=\"severity-chip " + normalized + "\">" +
            escapeHtml(normalized) + "<span style=\"margin-left:6px; opacity:0.85;\">" + count + "</span></span>";
    }

    private String renderEntryPointCard(EntryPointSummary entry) {
        if (entry == null) {
            return "";
        }
        String severity = entry.getSeverity() != null ? entry.getSeverity().toUpperCase(Locale.ROOT) : "UNKNOWN";
        String headerLabel = entry.getKey();
        if (headerLabel == null || headerLabel.isBlank()) {
            String method = entry.getMethod() != null ? entry.getMethod() : "";
            String path = entry.getPath() != null ? entry.getPath() : "";
            headerLabel = (method + " " + path).trim();
        }
        if (headerLabel == null || headerLabel.isBlank()) {
            headerLabel = "Endpoint";
        }

        StringBuilder card = new StringBuilder("<div class=\"attack-chain-card entry-point-card\">");
        card.append("<div class=\"attack-chain-header\">")
            .append("<div class=\"attack-chain-type\">")
            .append(escapeHtml(headerLabel))
            .append("</div>")
            .append("<div class=\"severity-badge ")
            .append(severity)
            .append("\">")
            .append(escapeHtml(severity))
            .append("</div>")
            .append("</div>");

        card.append("<div class=\"attack-chain-body\">")
            .append("<div><strong>Risk score:</strong> ")
            .append(entry.getRiskScore())
            .append("</div>");

        if (entry.getDataSensitivityLevel() != null && !entry.getDataSensitivityLevel().isBlank()) {
            card.append("<div class=\"sensitivity-badge\">Чувствительность данных: ")
                .append(escapeHtml(entry.getDataSensitivityLevel().toUpperCase(Locale.ROOT)))
                .append("</div>");
        }

        if (entry.getSensitiveFields() != null && !entry.getSensitiveFields().isEmpty()) {
            card.append("<div style=\"margin-top:8px;\"><strong>Чувствительные поля:</strong> ")
                .append(escapeHtml(formatSensitiveFields(entry.getSensitiveFields())))
                .append("</div>");
        }

        List<String> tags = new ArrayList<>();
        if (!entry.isRequiresAuth()) {
            tags.add(buildTagChip("Нет auth", "#fdecea", "#c0392b"));
        }
        if (!entry.isStrongAuth() && entry.isConsentRequired()) {
            tags.add(buildTagChip("Consent only", "#fff4e5", "#d35400"));
        }
        if (!entry.isStrongAuth() && !entry.isConsentRequired()) {
            tags.add(buildTagChip("Нет strong auth", "#fdecea", "#c0392b"));
        }
        if (entry.isOpenBanking()) {
            tags.add(buildTagChip("Open Banking", "#e8f5e9", "#27ae60"));
        }
        if (entry.isWeakProtection()) {
            tags.add(buildTagChip("Weak protection", "#fdecea", "#c0392b"));
        }
        if (entry.isHighRisk()) {
            tags.add(buildTagChip("High risk", "#fdecea", "#c0392b"));
        }

        if (!tags.isEmpty()) {
            card.append("<div style=\"margin-top:10px;\">");
            tags.forEach(card::append);
            card.append("</div>");
        }

        if (entry.getSignals() != null && !entry.getSignals().isEmpty()) {
            card.append("<div style=\"margin-top:10px;\">")
                .append("<strong>Сигналы:</strong> ");
            List<String> signals = entry.getSignals();
            int limit = Math.min(4, signals.size());
            for (int i = 0; i < limit; i++) {
                card.append(buildTagChip(signals.get(i), "#eef2ff", "#3f51b5"));
            }
            if (signals.size() > limit) {
                card.append(buildTagChip("+" + (signals.size() - limit), "#eef2ff", "#3f51b5"));
            }
            card.append("</div>");
        }

        card.append("</div></div>");
        return card.toString();
    }

    private String buildTagChip(String label, String background, String color) {
        if (label == null || label.isBlank()) {
            return "";
        }
        return "<span style=\"display:inline-block;padding:3px 10px;margin:3px;border-radius:999px;font-size:12px;font-weight:600;background:"
            + background + ";color:" + color + ";\">" + escapeHtml(label) + "</span>";
    }

    private String renderAttackChainCard(AttackChainSummary chain, int index) {
        if (chain == null) {
            return "";
        }
        String severity = chain.getSeverity() != null ? chain.getSeverity().toUpperCase(Locale.ROOT) : "UNKNOWN";
        StringBuilder card = new StringBuilder("<div class=\"attack-chain-card\">");
        card.append("<div class=\"attack-chain-header\">")
            .append("<div class=\"attack-chain-type\">#")
            .append(index)
            .append(" · ")
            .append(escapeHtml(formatChainType(chain.getType())))
            .append("</div>")
            .append("<div class=\"severity-badge ")
            .append(severity)
            .append("\">")
            .append(escapeHtml(severity))
            .append("</div>")
            .append("</div>");

        card.append("<div class=\"attack-chain-body\">");
        if (chain.getTarget() != null && !chain.getTarget().isBlank()) {
            card.append("<div><strong>Цель:</strong> ")
                .append(escapeHtml(chain.getTarget()))
                .append("</div>");
        }

        if (chain.getDataSensitivityLevel() != null && !chain.getDataSensitivityLevel().isBlank()) {
            card.append("<div class=\"sensitivity-badge\">Чувствительность данных: ")
                .append(escapeHtml(chain.getDataSensitivityLevel().toUpperCase(Locale.ROOT)))
                .append("</div>");
        }

        if (chain.getSensitiveFields() != null && !chain.getSensitiveFields().isEmpty()) {
            card.append("<div style=\"margin-top:8px;\"><strong>Чувствительные поля:</strong> ")
                .append(escapeHtml(formatSensitiveFields(chain.getSensitiveFields())))
                .append("</div>");
        }

        if (chain.getSteps() != null && !chain.getSteps().isEmpty()) {
            card.append("<div style=\"margin-top:10px;\"><strong>Шаги эксплуатации:</strong><ul>");
            for (String step : chain.getSteps()) {
                if (step != null) {
                    card.append("<li>").append(escapeHtml(step)).append("</li>");
                }
            }
            card.append("</ul></div>");
        }

        if (chain.getMetadata() != null && !chain.getMetadata().isEmpty()) {
            card.append("<div class=\"chain-meta\">");
            chain.getMetadata().forEach((k, v) -> {
                if (k != null && v != null) {
                    card.append("<span><strong>")
                        .append(escapeHtml(k))
                        .append(":</strong> ")
                        .append(escapeHtml(v))
                        .append("</span>");
                }
            });
            card.append("</div>");
        }

        if (chain.isExploitable()) {
            card.append("<div style=\"margin-top:12px; font-weight:600; color:#c0392b;\">Эксплуатация подтверждена без дополнительных предпосылок.</div>");
        }

        card.append("</div></div>");
        return card.toString();
    }

    private String formatChainType(String type) {
        if (type == null || type.isBlank()) {
            return "Attack Chain";
        }
        return switch (type.toUpperCase(Locale.ROOT)) {
            case "BOLA" -> "BOLA цепочка";
            case "ENTRY_POINT" -> "Открытая точка входа";
            case "LIST_TO_RESOURCE" -> "List → Resource цепочка";
            default -> type;
        };
    }

    private String formatSensitiveFields(List<String> fields) {
        return String.join(", ", fields);
    }
    
    private String buildImpactBlock(String impact) {
        if (impact == null || impact.isBlank()) {
            return "";
        }
        String severityClass = classifyImpactSeverity(impact);
        return String.format("""
            <div style=\"color: #2c3e50; font-size: 13px; margin-bottom: 8px;\">
                <strong>Impact:</strong>
                <span class=\"impact-chip %s\" style=\"margin-left: 8px;\">%s</span>
            </div>
            """,
            severityClass,
            escapeHtml(impact));
    }

    private String buildEvidenceBlock(String evidence) {
        if (evidence == null || evidence.isBlank()) {
            return "";
        }
        return String.format("""
            <div style=\"color: #555; font-size: 13px; margin-bottom: 8px; background: #f8f9fa; padding: 8px; border-radius: 4px; border-left: 3px solid #90caf9;\">
                <strong>Evidence:</strong> %s
            </div>
            """,
            escapeHtml(truncate(evidence, 320)));
    }

    private String renderImpactSummary(Map<String, Long> impactSummary) {
        if (impactSummary == null || impactSummary.isEmpty()) {
            return "";
        }
        StringBuilder section = new StringBuilder();
        section.append("<div class=\"impact-summary\"><h3 style=\"margin-bottom: 12px;\">Impact Highlights</h3>");
        impactSummary.entrySet().stream()
            .sorted(Map.Entry.comparingByValue(Comparator.reverseOrder()))
            .forEach(entry -> {
                String label = entry.getKey() != null ? entry.getKey().trim() : "";
                String severityClass = classifyImpactSeverity(label);
                section.append(String.format(
                    "<span class=\"impact-chip %s\">%s <strong>%d</strong></span>",
                    severityClass,
                    escapeHtml(label),
                    entry.getValue()));
            });
        section.append("</div>");
        return section.toString();
    }

    private String generateVulnerabilityCard(Vulnerability vuln,
                                             int sectionIndex,
                                             Map<String, List<DynamicFinding>> dynamicFindingMap) {
        StringBuilder card = new StringBuilder();
        
        String priorityClass = "priority-" + vuln.getPriority();
        card.append(String.format("""
            <div class="vuln-card %s %s" data-priority="%d" data-severity="%s" data-section="%d">
                <div class="vuln-title">
                    <span>%s %s</span>
                    <span>
                        <span class="vuln-badge badge-%s">%s</span>
                        %s
                    </span>
                </div>
                <div class="vuln-meta">
                    <strong>Эндпоинт:</strong> %s [%s] | 
                    <strong>Категория:</strong> %s |
                    <strong>Приоритет:</strong> <span style="background: %s; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px;">P%d</span> |
                    <strong>Risk Score:</strong> %d |
                    <strong>Confidence:</strong> %d%%
                </div>
            """,
            vuln.getSeverity().name(),
            priorityClass,
            vuln.getPriority(),
            vuln.getSeverity().name(),
            sectionIndex,
            vuln.getType().getDescription(),
            vuln.isGostRelated() ? "<span class=\"gost-badge\">ГОСТ</span>" : "",
            vuln.getSeverity().name(),
            vuln.getSeverity().getRussianName(),
            vuln.isGostRelated() ? "<span class=\"gost-badge\">ГОСТ</span>" : "",
            vuln.getEndpoint(),
            vuln.getMethod(),
            vuln.getOwaspCategory(),
            vuln.getPriority() == 1 ? "#e74c3c" : vuln.getPriority() == 2 ? "#e67e22" : vuln.getPriority() == 3 ? "#f39c12" : vuln.getPriority() == 4 ? "#3498db" : "#95a5a6",
            vuln.getPriority(),
            vuln.getRiskScore(),
            vuln.getConfidence()
        ));

        boolean dynamicVerified = hasDynamicVerification(vuln, dynamicFindingMap);
        List<String> schemaGuards = extractSchemaGuards(vuln);
        if (dynamicVerified || !schemaGuards.isEmpty()) {
            card.append("<div class=\"vuln-flags\">")
                .append(buildFlagRow(dynamicVerified, !schemaGuards.isEmpty()))
                .append("</div>");
        }
        
        // CWE/CVE информация (профессионализм!)
        if (vuln.getCwe() != null) {
            card.append(String.format("""
                <div class="vuln-meta" style="margin-top: 10px;">
                    <strong>CWE:</strong> %s
                    %s
                </div>
                """,
                vuln.getCwe(),
                vuln.getCveExamples() != null && !vuln.getCveExamples().isEmpty() 
                    ? " | <strong>CVE:</strong> " + String.join(", ", vuln.getCveExamples().subList(0, Math.min(3, vuln.getCveExamples().size())))
                    : ""
            ));
        }

        card.append(buildImpactBlock(vuln.getImpactLevel()));

        if (vuln.getEvidence() != null && !vuln.getEvidence().isBlank()) {
            card.append(String.format("""
                <div class="vuln-meta" style="margin-top: 6px;">
                    <strong>Evidence:</strong> %s
                </div>
                """,
                escapeHtml(truncate(vuln.getEvidence(), 400))));
        }
        if (!schemaGuards.isEmpty()) {
            card.append(buildSchemaGuardList(schemaGuards));
        }
        
        // ИННОВАЦИЯ: Добавляем примеры кода из CodeExamples
        com.vtb.scanner.knowledge.CodeExamples.CodeExample codeExample = 
            com.vtb.scanner.knowledge.CodeExamples.getExample(vuln.getType());
        if (codeExample != null && codeExample.getGoodCode() != null && !codeExample.getGoodCode().trim().isEmpty()) {
            card.append(String.format("""
                <div class="vuln-recommendation" style="margin-top: 10px;">
                    <strong>💻 Пример безопасного кода:</strong>
                    <pre style="background: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; margin-top: 8px; font-size: 12px;"><code>%s</code></pre>
                </div>
                """,
                escapeHtml(codeExample.getGoodCode())
            ));
        }
        
        card.append(String.format("""
                <div class="vuln-description">
                    <strong>Описание:</strong> %s
                </div>
                <div class="vuln-recommendation">
                    <strong>💡 Рекомендация:</strong> %s
                </div>
            </div>
            """,
            vuln.getDescription(),
            vuln.getRecommendation()
        ));
        
        return card.toString();
    }
    
    private String buildContextBadge(String context) {
        if (context == null || context.isBlank()) {
            return "";
        }
        String label = context.toUpperCase(Locale.ROOT);
        try {
            ContextAnalyzer.APIContext apiContext = ContextAnalyzer.APIContext.valueOf(context.toUpperCase(Locale.ROOT));
            label = apiContext.getDescription();
        } catch (IllegalArgumentException ignored) {
            // fallback to original label
        }
        return "<div style=\"margin-top: 12px;\"><span style=\"display:inline-flex;align-items:center;gap:8px;background:rgba(255,255,255,0.18);color:white;padding:6px 14px;border-radius:999px;font-size:13px;font-weight:600;letter-spacing:0.4px;text-transform:uppercase;\">Контекст: " + label + "</span></div>";
    }

    private String buildHealthBadge(long healthScore) {
        if (healthScore <= 0) {
            return "";
        }
        String color = healthScore >= 80 ? "#2ecc71" : (healthScore >= 60 ? "#f1c40f" : "#e74c3c");
        return "<div style=\"margin-top: 8px;\"><span style=\"display:inline-flex;align-items:center;gap:8px;background:white;color:" + color + ";padding:6px 14px;border-radius:999px;font-size:13px;font-weight:600;\">API Health Score: " + healthScore + "/100</span></div>";
    }

    private String renderContractViolations(ScanResult result) {
        if (result.getContractViolations() == null || result.getContractViolations().isEmpty()) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        builder.append("""
            <div class="contract-violations" style="padding: 30px;">
                <h2 style="margin-bottom: 15px; color: #2c3e50;">Нарушения контрактов (API Contract)</h2>
                <p style="color:#555; margin-bottom:18px;">Выявлено <strong>%d</strong> несоответствий спецификации. Устраните их до публикации API.</p>
        """.formatted(result.getContractViolations().size()));

        for (ContractViolation violation : result.getContractViolations()) {
            Severity severity = violation.getSeverity() != null ? violation.getSeverity() : Severity.MEDIUM;
            String severityBadge = buildSeverityBadge(severity);
            String color = severityColor(severity);
            String typeDescription = violation.getType() != null ? violation.getType().getDescription() : "Нарушение контракта";

            builder.append(String.format("""
                <div style="border-left:4px solid %s; background:#fdfdfd; padding:18px; margin-bottom:16px; border-radius:8px; box-shadow:0 2px 6px rgba(0,0,0,0.05);">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                        <h3 style="margin:0; font-size:18px; color:#2c3e50;">%s</h3>
                        %s
                    </div>
                    <div style="font-size:13px; color:#7f8c8d; margin-bottom:8px;">
                        <strong>Эндпоинт:</strong> <code>%s [%s]</code>
                    </div>
                    <div style="font-size:14px; color:#34495e; margin-bottom:6px;">%s</div>
                    <div style="display:flex; flex-wrap:wrap; gap:12px; color:#555; font-size:13px;">
                        <div><strong>Ожидалось:</strong> %s</div>
                        <div><strong>Фактически:</strong> %s</div>
                    </div>
                </div>
            """,
                color,
                typeDescription,
                severityBadge,
                violation.getEndpoint() != null ? violation.getEndpoint() : "N/A",
                violation.getMethod() != null ? violation.getMethod() : "N/A",
                violation.getDescription() != null ? violation.getDescription() : "Описание отсутствует",
                violation.getExpected() != null ? violation.getExpected() : "N/A",
                violation.getActual() != null ? violation.getActual() : "N/A"
            ));
        }

        builder.append("</div>");
        return builder.toString();
    }

    private String buildSeverityBadge(Severity severity) {
        return "<span style=\"background:" + severityColor(severity) + "; color:white; padding:4px 12px; border-radius:12px; font-size:12px; font-weight:600;\">" + severity.name() + "</span>";
    }

    private String severityColor(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "#e74c3c";
            case HIGH -> "#e67e22";
            case MEDIUM -> "#f39c12";
            case LOW -> "#3498db";
            case INFO -> "#95a5a6";
        };
    }
    
    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#39;");
    }

    private String classifyImpactSeverity(String impact) {
        if (impact == null) {
            return "INFO";
        }
        String lower = impact.toLowerCase(Locale.ROOT);
        if (lower.contains("treasury_flow") || lower.contains("financial_fraud") ||
            lower.contains("payout_flow") || lower.contains("gov_flow") ||
            lower.contains("consent_flow") || lower.contains("loan_flow") ||
            lower.contains("telecom_core") || lower.contains("telecom_flow") ||
            lower.contains("connected_car") || lower.contains("vehicle_control") ||
            lower.contains("telematics") || lower.contains("remote_control")) {
            return "CRITICAL";
        }
        if (lower.contains("order_flow") || lower.contains("marketplace_abuse") ||
            lower.contains("onboarding_flow") || lower.contains("auth_abuse") ||
            lower.contains("password_reset") || lower.contains("session_flow") ||
            lower.contains("refund_flow") || lower.contains("msisdn_exposure") ||
            lower.contains("vin_exposure") || lower.contains("sim_swap")) {
            return "HIGH";
        }
        if (lower.contains("dos_risk") || lower.contains("abuse") || lower.contains("session") ||
            lower.contains("impact") || lower.contains("risk")) {
            return "MEDIUM";
        }
        return "INFO";
    }

    private String truncate(String text, int maxLength) {
        if (text == null) {
            return "";
        }
        if (text.length() <= maxLength) {
            return text;
        }
        return text.substring(0, Math.max(0, maxLength - 3)) + "...";
    }

    private String formatDouble(double value) {
        if (Double.isNaN(value) || Double.isInfinite(value)) {
            return "0.0";
        }
        return new DecimalFormat("#0.0").format(value);
    }

    private String formatPercent(double ratio) {
        double clamped = Math.max(0d, Math.min(ratio, 1d));
        return new DecimalFormat("#0.0").format(clamped * 100d) + "%";
    }
    
    @Override
    public String getFileExtension() {
        return "html";
    }

    private String renderDataProtectionSection(DataProtectionSummary summary) {
        if (summary == null || summary.getExposures() == null || summary.getExposures().isEmpty()) {
            return "";
        }

        StringBuilder section = new StringBuilder();
        section.append("<section class=\"data-protection-section\">\n");
        section.append("<h2>Data Protection Flow</h2>\n");
        section.append("<p style=\"margin-top:8px;color:#455a64;\">Идентифицированные цепочки обработки чувствительных данных (PII) и связанные риски.</p>\n");

        section.append("<div class=\"dpi-grid\">\n");
        section.append(dataStatCard("PII сигналы", summary.getTotalSignals(), "обнаружено индикаторов"));
        section.append(dataStatCard("Критичные экспозиции", summary.getCriticalExposures(), "High/Critical"));
        section.append(dataStatCard("Неавторизованные потоки", summary.getUnauthorizedFlows(), "BOLA/BFLA"));
        section.append(dataStatCard("Риски транспорта", summary.isInsecureTransportDetected() ? 1 : 0, "HTTP/ws обнаружены"));
        section.append(dataStatCard("Consent gaps", summary.getConsentGapCount(), "отсутствие согласий"));
        section.append(dataStatCard("Storage exposures", summary.isStorageExposureDetected() ? 1 : 0, "экспорт/выгрузки"));
        section.append(dataStatCard("Logging risks", summary.isLoggingExposureDetected() ? 1 : 0, "PII в логах"));
        section.append("</div>\n");

        section.append("<div class=\"pii-list\">\n");
        for (PiiExposure exposure : summary.getExposures()) {
            section.append(renderPiiExposure(exposure));
        }
        section.append("</div>\n");

        if (summary.getHighRiskChains() != null && !summary.getHighRiskChains().isEmpty()) {
            section.append("<h3 style=\"margin-top:22px; color:#2c3e50;\">Высокорисковые цепочки</h3>\n");
            section.append("<ul class=\"recommendations-list\">\n");
            for (String chain : summary.getHighRiskChains()) {
                section.append("<li>" + escapeHtml(chain) + "</li>\n");
            }
            section.append("</ul>\n");
        }

        if (summary.getRecommendedActions() != null && !summary.getRecommendedActions().isEmpty()) {
            section.append("<h3 style=\"margin-top:18px; color:#2c3e50;\">Рекомендации</h3>\n");
            section.append("<ul class=\"recommendations-list\">\n");
            for (String action : summary.getRecommendedActions()) {
                section.append("<li>" + escapeHtml(action) + "</li>\n");
            }
            section.append("</ul>\n");
        }

        section.append("</section>\n");
        return section.toString();
    }

    private String renderSchemaGuardSection(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return "";
        }
        EnumMap<Severity, Integer> severityDistribution = new EnumMap<>(Severity.class);
        Map<String, Integer> reasonCounts = new LinkedHashMap<>();
        int guardHits = 0;
        for (Vulnerability vuln : vulnerabilities) {
            if (vuln == null) {
                continue;
            }
            List<String> guards = extractSchemaGuards(vuln);
            if (guards.isEmpty()) {
                continue;
            }
            guardHits++;
            severityDistribution.merge(vuln.getSeverity(), 1, Integer::sum);
            for (String guard : guards) {
                if (guard == null || guard.isBlank()) {
                    continue;
                }
                reasonCounts.merge(guard, 1, Integer::sum);
            }
        }
        if (guardHits == 0) {
            return "";
        }
        StringBuilder section = new StringBuilder();
        section.append("<section class=\"schema-guard-section\" style=\"padding:25px 30px; border-top:1px solid #ecf0f1;\">\n");
        section.append("<h2 style=\"margin-bottom:8px;\">Schema Guard Coverage</h2>\n");
        section.append("<p style=\"color:#566573; margin-bottom:18px;\">Сниженные риски благодаря OpenAPI ограничениям (enum/pattern/min-max).</p>\n");

        String topReason = reasonCounts.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .map(entry -> entry.getKey() + " (" + entry.getValue() + ")")
            .findFirst()
            .orElse("—");
        String severityBreakdown = severityDistribution.entrySet().stream()
            .sorted(Map.Entry.<Severity, Integer>comparingByValue().reversed())
            .map(entry -> entry.getKey().name() + ":" + entry.getValue())
            .collect(Collectors.joining(" · "));

        section.append("<div class=\"summary-grid\" style=\"margin-top:12px;\">\n");
        section.append(summaryCard("Schema Guard hits", guardHits, "уязвимостей пересчитано"));
        section.append(summaryCard("Severity mix", severityBreakdown.isBlank() ? "—" : severityBreakdown, "распределение рисков"));
        section.append(summaryCard("Top guard", topReason, "ведущий сигнал схемы"));
        section.append("</div>\n");

        section.append("<div style=\"margin-top:18px;\">\n");
        section.append("<h3 style=\"font-size:16px; margin-bottom:6px; color:#2c3e50;\">Основные ограничения</h3>\n");
        section.append("<ul class=\"schema-guard-list\" style=\"margin-left:0;\">\n");
        reasonCounts.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(6)
            .forEach(entry -> section.append("<li>")
                .append(escapeHtml(entry.getKey()))
                .append(" — ")
                .append(entry.getValue())
                .append("</li>\n"));
        section.append("</ul>\n");
        section.append("</div>\n");
        section.append("</section>\n");
        return section.toString();
    }

    private String dataStatCard(String title, int value, String subtitle) {
        return "<div class=\"dpi-card\">"
            + "<h3>" + escapeHtml(title) + "</h3>"
            + "<div class=\"value\">" + value + "</div>"
            + "<div class=\"sub\">" + escapeHtml(subtitle) + "</div>"
            + "</div>";
    }

    private String renderPiiExposure(PiiExposure exposure) {
        StringBuilder card = new StringBuilder();
        card.append("<div class=\"pii-item\">\n");
        card.append("<h3>" + escapeHtml(exposure.getMethod() + " " + exposure.getEndpoint()) + "</h3>\n");
        card.append("<div class=\"pii-meta\">Severity: <span class=\"severity-chip "
            + (exposure.getSeverity() != null ? exposure.getSeverity().name() : "INFO")
            + "\">"
            + (exposure.getSeverity() != null ? exposure.getSeverity().name() : "INFO")
            + "</span></div>\n");

        card.append("<div class=\"pii-tags\">\n");
        if (exposure.getSignals() != null) {
            for (String signal : exposure.getSignals()) {
                card.append("<span class=\"pii-tag\">" + escapeHtml(signal) + "</span>\n");
            }
        }
        if (Boolean.TRUE.equals(exposure.isUnauthorizedAccess())) {
            card.append("<span class=\"pii-tag\" style=\"background:#fdecea;color:#c0392b;\">Unauthorized Flow</span>\n");
        }
        if (Boolean.TRUE.equals(exposure.isConsentMissing())) {
            card.append("<span class=\"pii-tag\" style=\"background:#fff3cd;color:#d48806;\">Consent Missing</span>\n");
        }
        if (Boolean.TRUE.equals(exposure.isInsecureTransport())) {
            card.append("<span class=\"pii-tag\" style=\"background:#fdecea;color:#c0392b;\">Insecure Transport</span>\n");
        }
        card.append("</div>\n");

        if (exposure.getVulnerabilityIds() != null && !exposure.getVulnerabilityIds().isEmpty()) {
            card.append("<div class=\"pii-meta\">Связанные ID: "
                + escapeHtml(String.join(", ", exposure.getVulnerabilityIds())) + "</div>\n");
        }

        card.append("</div>\n");
        return card.toString();
    }

    private String renderExecutiveSummary(ScanResult result) {
        if (result == null) {
            return "";
        }
        ExecutiveSummary summary = result.getExecutiveSummary();
        ScanStatistics stats = result.getStatistics();
        if (stats == null) {
            stats = ScanStatistics.builder().build();
        }

        int critical = summary != null ? summary.getCriticalVulnerabilities()
            : stats != null ? stats.getCriticalVulnerabilities() : result.getVulnerabilityCountBySeverity(Severity.CRITICAL);
        int high = summary != null ? summary.getHighVulnerabilities()
            : stats != null ? stats.getHighVulnerabilities() : result.getVulnerabilityCountBySeverity(Severity.HIGH);
        int medium = summary != null ? summary.getMediumVulnerabilities()
            : stats != null ? stats.getMediumVulnerabilities() : result.getVulnerabilityCountBySeverity(Severity.MEDIUM);
        int low = summary != null ? summary.getLowVulnerabilities()
            : stats != null ? stats.getLowVulnerabilities() : result.getVulnerabilityCountBySeverity(Severity.LOW);
        int info = summary != null ? summary.getInfoVulnerabilities()
            : stats != null ? stats.getInfoVulnerabilities() : result.getVulnerabilityCountBySeverity(Severity.INFO);
        int total = summary != null ? summary.getTotalVulnerabilities()
            : stats != null ? stats.getTotalVulnerabilities() : result.getVulnerabilities().size();

        int criticalExposures = summary != null ? summary.getCriticalExposures()
            : result.getDataProtection() != null ? result.getDataProtection().getCriticalExposures() : 0;
        int consentGaps = summary != null ? summary.getConsentGaps()
            : result.getDataProtection() != null ? result.getDataProtection().getConsentGapCount() : 0;
        int unauthorizedFlows = summary != null ? summary.getUnauthorizedFlows()
            : result.getDataProtection() != null ? result.getDataProtection().getUnauthorizedFlows() : 0;
        int secretLeaks = summary != null ? summary.getSecretLeaks()
            : (int) result.getVulnerabilities().stream().filter(v -> v.getType() == VulnerabilityType.SECRET_LEAK).count();
        int shadowApis = summary != null ? summary.getShadowApis()
            : (int) result.getVulnerabilities().stream().filter(v -> v.getType() == VulnerabilityType.SHADOW_API).count();

        String riskLevel = summary != null && summary.getRiskLevel() != null ? summary.getRiskLevel()
            : result.getRiskLevel() != null ? result.getRiskLevel() : "UNKNOWN";
        String riskClass = "risk-badge " + riskLevel.replaceAll("[^A-Z]", "").toUpperCase(Locale.ROOT);
        String apiContext = summary != null && summary.getApiContext() != null
            ? translateContext(summary.getApiContext())
            : translateContext(result.getApiContext());

        List<String> findings = summary != null ? summary.getKeyFindings() : result.getKeyFindings();
        List<String> recommendedActions = summary != null ? summary.getRecommendedActions() : Collections.emptyList();
 
        StringBuilder section = new StringBuilder();
        section.append("<section class=\"summary-section\">\n");
        section.append("<div class=\"summary-header\">\n");
        section.append("<h2>Executive Summary</h2>\n");
        section.append("<span class=\"" + riskClass + "\">"
            + escapeHtml(riskLevel) + " Risk</span>\n");
        section.append("</div>\n");
 
        section.append("<div class=\"summary-grid\">\n");
        int riskScore = summary != null ? summary.getRiskScore() : result.getOverallRiskScore();
        section.append(summaryCard("Risk Score", riskScore + "/100", "Оценка совокупного риска"));
        section.append(summaryCard("Всего уязвимостей", total, "Включая все уровни критичности"));
        section.append(summaryCard("Критичные экспозиции", criticalExposures, "PII / business flow"));
        section.append(summaryCard("Secrets / Shadow", secretLeaks + shadowApis, "Секреты и dev окружения"));
        section.append(summaryCard("Consent / Unauthorized", consentGaps + unauthorizedFlows, "Нарушения согласий и потоков"));
        section.append(summaryCard("API Context", apiContext, "Определённый тип API"));
        section.append("</div>\n");
 
        section.append(renderSeverityHeatmap(critical, high, medium, low, info));
 
        if (!findings.isEmpty() || consentGaps > 0) {
            section.append("<ul class=\"summary-findings\">\n");
            for (String finding : findings) {
                section.append("<li>" + escapeHtml(finding) + "</li>\n");
            }
            if (consentGaps > 0) {
                section.append("<li>Отсутствуют согласия (consent gaps): " + consentGaps + "</li>\n");
            }
            if (unauthorizedFlows > 0) {
                section.append("<li>Нарушенные потоки авторизации: " + unauthorizedFlows + "</li>\n");
            }
            section.append("</ul>\n");
        }

        if (!recommendedActions.isEmpty()) {
            section.append("<div style=\"margin-top:16px;\"><strong>Рекомендуемые шаги:</strong></div>\n");
            section.append("<ul class=\"summary-findings\">\n");
            for (String action : recommendedActions) {
                section.append("<li>" + escapeHtml(action) + "</li>\n");
            }
            section.append("</ul>\n");
        }
 
        section.append("</section>\n");
        return section.toString();
    }

    private String renderTrendSection(ScanResult result) {
        if (result == null || result.getStatistics() == null && (result.getVulnerabilities() == null || result.getVulnerabilities().isEmpty())) {
            return "";
        }
        ScanStatistics stats = result.getStatistics();
        int totalVulns = stats != null ? stats.getTotalVulnerabilities() : result.getVulnerabilities().size();
        if (totalVulns <= 0) {
            return "";
        }
        BenchmarkComparator.BenchmarkComparison comparison = BenchmarkComparator.compare(result);
        DecimalFormat df = new DecimalFormat("0.0");

        int critical = stats != null ? stats.getCriticalVulnerabilities() : result.getVulnerabilityCountBySeverity(Severity.CRITICAL);
        int high = stats != null ? stats.getHighVulnerabilities() : result.getVulnerabilityCountBySeverity(Severity.HIGH);
        int medium = stats != null ? stats.getMediumVulnerabilities() : result.getVulnerabilityCountBySeverity(Severity.MEDIUM);
        int low = stats != null ? stats.getLowVulnerabilities() : result.getVulnerabilityCountBySeverity(Severity.LOW);
        int info = stats != null ? stats.getInfoVulnerabilities() : result.getVulnerabilityCountBySeverity(Severity.INFO);

        StringBuilder section = new StringBuilder();
        section.append("<section class=\"trend-section\" style=\"padding:26px 32px; border-top:1px solid #edf1f7; background:#fbfcff;\">\n");
        section.append("<h2 style=\"margin-bottom:8px;\">Risk Trend & Benchmarks</h2>\n");
        section.append("<p style=\"color:#546e7a; margin-bottom:16px;\">Позиция относительно индустрии и распределение критичности.</p>\n");

        String density = df.format(comparison.getVulnsPerEndpoint()) + " vs " + df.format(comparison.getIndustryAvgVulnsPerEndpoint());
        section.append("<div class=\"summary-grid\" style=\"margin-bottom:18px;\">\n");
        section.append(summaryCard("Security score", comparison.getOverallSecurityScore() + "/100", comparison.getOverallRating()));
        section.append(summaryCard("Vulns / endpoint", density, comparison.getVulnsDensity()));
        section.append(summaryCard("Best practice", comparison.getBestPracticeLevel(), "Score " + comparison.getBestPracticeScore()));
        section.append("</div>\n");

        section.append("<div class=\"trend-bar\" style=\"display:flex; height:32px; border-radius:18px; overflow:hidden; background:#e9edf7;\">\n");
        section.append(buildTrendSegment("CRITICAL", critical, totalVulns, "#c62828"));
        section.append(buildTrendSegment("HIGH", high, totalVulns, "#ef6c00"));
        section.append(buildTrendSegment("MEDIUM", medium, totalVulns, "#f9a825"));
        section.append(buildTrendSegment("LOW", low, totalVulns, "#78909c"));
        section.append(buildTrendSegment("INFO", info, totalVulns, "#90a4ae"));
        section.append("</div>\n");

        double criticalShare = totalVulns > 0 ? (critical * 100.0 / totalVulns) : 0;
        double highShare = totalVulns > 0 ? (high * 100.0 / totalVulns) : 0;
        section.append("<p style=\"margin-top:10px; color:#455a64; font-size:13px;\">Critical "
            + df.format(criticalShare) + "% · High " + df.format(highShare) + "% · ГОСТ score "
            + comparison.getGostComplianceScore() + "/100</p>\n");

        section.append("<ul style=\"margin:10px 0 0 18px; color:#546e7a; font-size:13px;\">\n");
        section.append("<li>Industry density: ").append(comparison.getVulnsDensity()).append("</li>\n");
        section.append("<li>Best practice cap: ≤ ").append(comparison.getBestPracticeMaxTotal()).append(" findings (")
            .append(comparison.getBestPracticeLevel()).append(")</li>\n");
        section.append("<li>ГОСТ readiness: ").append(comparison.getGostComplianceLevel()).append("</li>\n");
        section.append("</ul>\n");
        section.append("</section>\n");
        return section.toString();
    }

    private String buildTrendSegment(String label, int count, int total, String color) {
        if (total <= 0 || count <= 0) {
            return "";
        }
        double share = (double) count / total * 100;
        double width = Math.max(5, share);
        return "<div style=\"flex:0 0 " + width + "%; background:" + color
            + "; display:flex; align-items:center; justify-content:center; color:#fff; font-size:11px; font-weight:600;\">"
            + label + " (" + count + ")</div>";
    }

    private String summaryCard(String label, Object value, String subtitle) {
        return "<div class=\"summary-card\">"
            + "<div class=\"label\">" + escapeHtml(String.valueOf(label)) + "</div>"
            + "<div class=\"value\">" + escapeHtml(String.valueOf(value)) + "</div>"
            + "<div class=\"sub\">" + escapeHtml(subtitle) + "</div>"
            + "</div>";
    }

    private String renderSeverityHeatmap(int critical, int high, int medium, int low, int info) {
        StringBuilder heatmap = new StringBuilder();
        heatmap.append("<div class=\"heatmap\">\n");
        heatmap.append(heatmapCell("Critical", critical, "CRITICAL"));
        heatmap.append(heatmapCell("High", high, "HIGH"));
        heatmap.append(heatmapCell("Medium", medium, "MEDIUM"));
        heatmap.append(heatmapCell("Low", low, "LOW"));
        heatmap.append(heatmapCell("Info", info, "INFO"));
        heatmap.append("</div>\n");
        return heatmap.toString();
    }

    private String heatmapCell(String label, int value, String severityClass) {
        return "<div class=\"heatmap-cell " + severityClass + "\">" + escapeHtml(String.valueOf(value)) + "<div style=\"font-size:12px; margin-top:4px;\">"
            + escapeHtml(label) + "</div></div>";
    }

    private String renderDynamicSection(ScanResult result) {
        DynamicScanReport report = result != null ? result.getDynamicScanReport() : null;
        if (report == null || (!report.hasFindings() && (report.getTelemetryNotices() == null || report.getTelemetryNotices().isEmpty()))) {
            return "";
        }

        StringBuilder section = new StringBuilder();
        section.append("<section class=\"dynamic-scan-section\">\n");
        section.append("<h2>Dynamic Scenario Insights</h2>\n");
        section.append("<p style=\"margin-top: 10px; color: #455a64;\">Результаты воспроизведения бизнес-сценариев и gentle runtime-проверок.</p>\n");
        section.append(renderDynamicMetrics(report, result));
        section.append(renderDynamicPayloadMatrix(report));

        if (report.hasFindings()) {
            section.append("<div class=\"dynamic-findings-grid\">\n");
            int index = 1;
            for (DynamicFinding finding : report.getFindings()) {
                if (finding == null) {
                    continue;
                }
                section.append(renderDynamicFindingCard(finding, index++));
            }
            section.append("</div>\n");
        }

        if (report.getTelemetryNotices() != null && !report.getTelemetryNotices().isEmpty()) {
            section.append("<div class=\"telemetry-notes\" style=\"margin-top:16px;background:#f0f4ff;padding:12px;border-radius:8px;\">");
            section.append("<strong>Telemetry:</strong>");
            section.append("<ul style=\"margin:8px 0 0 16px;\">");
            for (String notice : report.getTelemetryNotices()) {
                section.append("<li>").append(escapeHtml(notice)).append("</li>");
            }
            section.append("</ul></div>\n");
        }

        section.append("</section>\n");
        return section.toString();
    }

    private String renderDynamicMetrics(DynamicScanReport report, ScanResult result) {
        int executedScenarios = report.getExecutedScenarios();
        int executedSteps = report.getExecutedSteps();
        int payloadTotal = report.getPayloadBlueprints();
        int payloadMatched = report.getPayloadsMatched();
        int dynamicFindings = report.getFindings() != null ? report.getFindings().size() : 0;
        long highCritical = result != null
            ? result.getVulnerabilityCountBySeverity(Severity.CRITICAL) + result.getVulnerabilityCountBySeverity(Severity.HIGH)
            : 0;
        double precision = highCritical == 0 ? 0d : (double) dynamicFindings / highCritical;
        double recall = payloadTotal == 0 ? 0d : (double) payloadMatched / payloadTotal;
        int schemaGuards = countSchemaGuardVulns(result != null ? result.getVulnerabilities() : Collections.emptyList());

        StringBuilder grid = new StringBuilder();
        grid.append("<div class=\"summary-grid\" style=\"margin-top:16px;\">\n");
        grid.append(summaryCard("Scenarios executed", executedScenarios, "Динамических трасс"));
        grid.append(summaryCard("Steps replayed", executedSteps, "HTTP вызовов"));
        grid.append(summaryCard("Payload coverage", payloadMatched + "/" + Math.max(payloadTotal, 0), "Активные блупринты"));
        grid.append(summaryCard("Dynamic confirmations", dynamicFindings, "Найдены при реплее"));
        grid.append(summaryCard("Synthetic traces", report.getAppendedTraces(), "Добавлено маршрутов"));
        grid.append(summaryCard("Precision proxy", formatPercent(precision), "Доля High риска подтверждена"));
        grid.append(summaryCard("Schema Guard downgrades", schemaGuards, "Уменьшено схемой"));
        grid.append(summaryCard("Recall proxy", formatPercent(recall), "Покрыто payload-ами"));
        grid.append("</div>\n");
        return grid.toString();
    }

    private String renderDynamicFindingCard(DynamicFinding finding, int index) {
        String severity = finding.getSeverity() != null ? finding.getSeverity().name() : "INFO";
        StringBuilder card = new StringBuilder("<div class=\"dynamic-finding-card\">");
        card.append("<div class=\"dynamic-finding-header\">")
            .append("<div class=\"dynamic-finding-title\">")
            .append("#").append(index).append(" · ")
            .append(escapeHtml(finding.getType() != null ? finding.getType().name() : "FINDING"))
            .append("</div>")
            .append("<div class=\"severity-badge ").append(severity).append("\">")
            .append(escapeHtml(severity))
            .append("</div>")
            .append("</div>");

        card.append("<div class=\"dynamic-finding-body\">");
        if (finding.getEndpoint() != null) {
            card.append("<div><strong>Endpoint:</strong> ")
                .append(escapeHtml(finding.getMethod() != null ? finding.getMethod() : "GET"))
                .append(" ")
                .append(escapeHtml(finding.getEndpoint()))
                .append("</div>");
        }
        if (finding.getDescription() != null) {
            card.append("<div style=\"margin-top:6px;\">")
                .append(escapeHtml(finding.getDescription()))
                .append("</div>");
        }
        if (finding.getEvidence() != null) {
            card.append("<div class=\"dynamic-evidence\" style=\"margin-top:8px;color:#546e7a;font-size:13px;\">")
                .append("<strong>Evidence:</strong> ")
                .append(escapeHtml(finding.getEvidence()))
                .append("</div>");
        }
        card.append("</div>");
        card.append("</div>");
        return card.toString();
    }

    private String renderDynamicPayloadMatrix(DynamicScanReport report) {
        if (report == null || report.getPayloadBlueprints() <= 0) {
            return "";
        }
        int total = report.getPayloadBlueprints();
        int matched = Math.min(report.getPayloadsMatched(), total);
        int unmatched = Math.max(total - matched, 0);
        int appended = Math.max(report.getAppendedTraces(), 0);
        StringBuilder table = new StringBuilder();
        table.append("<div class=\"dynamic-payload-matrix\" style=\"margin-top:18px; background:#f9fafc; border:1px solid #e1e5ee; border-radius:10px; padding:18px;\">\n");
        table.append("<h3 style=\"margin-bottom:12px; color:#2c3e50;\">Payload Coverage</h3>\n");
        table.append("<table style=\"width:100%; border-collapse:collapse; font-size:13px;\">\n");
        table.append("<thead><tr style=\"background:#eef2ff; color:#3f51b5;\">\n");
        table.append("<th style=\"padding:8px; text-align:left;\">Тип</th>");
        table.append("<th style=\"padding:8px; text-align:center;\">Всего</th>");
        table.append("<th style=\"padding:8px; text-align:center;\">Matched</th>");
        table.append("<th style=\"padding:8px; text-align:center;\">Pending</th>");
        table.append("<th style=\"padding:8px; text-align:center;\">Appended traces</th>");
        table.append("</tr></thead>\n");
        table.append("<tbody>\n");
        table.append("<tr style=\"border-bottom:1px solid #e1e5ee;\">\n");
        table.append("<td style=\"padding:8px;\">Blueprint payloads</td>");
        table.append("<td style=\"padding:8px; text-align:center; font-weight:600;\">" + total + "</td>");
        table.append("<td style=\"padding:8px; text-align:center; color:#2e7d32; font-weight:600;\">" + matched + "</td>");
        table.append("<td style=\"padding:8px; text-align:center; color:#ef6c00; font-weight:600;\">" + unmatched + "</td>");
        table.append("<td style=\"padding:8px; text-align:center;\">" + appended + "</td>");
        table.append("</tr>\n");
        table.append("</tbody></table>\n");
        table.append("<p style=\"margin-top:10px; color:#546e7a; font-size:12px;\">* Matched — payloadы, которые были встроены в сценарии. Pending — ожидают попадания в релевантные трассы.</p>\n");
        table.append("</div>\n");
        return table.toString();
    }
}

