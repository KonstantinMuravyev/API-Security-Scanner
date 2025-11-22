package com.vtb.scanner.reports;

import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.*;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import com.vtb.scanner.benchmark.BenchmarkComparator;
import com.vtb.scanner.models.ScanResult;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;

/**
 * Генератор PDF отчетов для руководства
 * Executive Summary - краткий отчет для менеджмента
 */
@Slf4j
public class PdfReportGenerator implements ReportGenerator {
    
    private static final DateTimeFormatter DATE_FORMATTER = 
        DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss");
    
    @Override
    public void generate(ScanResult result, Path outputPath) throws IOException {
        log.info("Генерация PDF отчета: {}", outputPath);
        
        // КРИТИЧНО: Защита от NPE
        if (result == null) {
            throw new IllegalArgumentException("ScanResult не может быть null");
        }
        
        try {
            PdfWriter writer = new PdfWriter(outputPath.toString());
            PdfDocument pdf = new PdfDocument(writer);
            Document document = new Document(pdf);
            
            // Заголовок
            addTitle(document, result);
            
            // Executive Summary
            addExecutiveSummary(document, result);
            
            // Security Score
            addSecurityScore(document, result);
            
            // Топ уязвимости
            addTopVulnerabilities(document, result);
            
            // ГОСТ раздел (если включен)
            if (result.getStatistics() != null && result.getStatistics().isGostCheckEnabled()) {
                addGostSection(document, result);
            }
            
            // Рекомендации
            addRecommendations(document, result);
            
            document.close();
            
            log.info("PDF отчет сохранен: {}", outputPath);
            
        } catch (Exception e) {
            throw new IOException("Ошибка генерации PDF: " + e.getMessage(), e);
        }
    }
    
    private void addTitle(Document document, ScanResult result) {
        Paragraph title = new Paragraph("API Security Scan Report")
            .setFontSize(24)
            .setBold()
            .setTextAlignment(TextAlignment.CENTER);
        document.add(title);
        
        // КРИТИЧНО: Защита от NPE
        String apiName = result.getApiName() != null ? result.getApiName() : "Unknown";
        String apiVersion = result.getApiVersion() != null ? result.getApiVersion() : "Unknown";
        
        Paragraph subtitle = new Paragraph(apiName + " v" + apiVersion)
            .setFontSize(16)
            .setTextAlignment(TextAlignment.CENTER);
        document.add(subtitle);
        
        if (result.getScanTimestamp() != null) {
            Paragraph date = new Paragraph("Дата сканирования: " + 
                    result.getScanTimestamp().format(DATE_FORMATTER))
                .setFontSize(12)
                .setTextAlignment(TextAlignment.CENTER)
                .setMarginBottom(20);
            document.add(date);
        }
    }
    
    private void addExecutiveSummary(Document document, ScanResult result) {
        document.add(new Paragraph("Executive Summary")
            .setFontSize(18)
            .setBold()
            .setMarginTop(10));
        
        Table table = new Table(UnitValue.createPercentArray(new float[]{1, 1}));
        table.setWidth(UnitValue.createPercentValue(100));
        
        // КРИТИЧНО: Защита от NPE
        String apiName = result.getApiName() != null ? result.getApiName() : "Unknown";
        String apiVersion = result.getApiVersion() != null ? result.getApiVersion() : "Unknown";
        String targetUrl = result.getTargetUrl() != null ? result.getTargetUrl() : "N/A";
        
        table.addCell(createCell("API", apiName));
        table.addCell(createCell("Версия", apiVersion));
        table.addCell(createCell("Target URL", targetUrl));
        
        if (result.getStatistics() != null) {
            table.addCell(createCell("Эндпоинтов", String.valueOf(result.getStatistics().getTotalEndpoints())));
            table.addCell(createCell("Время сканирования", result.getStatistics().getScanDurationMs() + " мс"));
        } else {
            table.addCell(createCell("Эндпоинтов", "0"));
            table.addCell(createCell("Время сканирования", "N/A"));
        }
        
        table.addCell(createCell("Всего уязвимостей", 
            result.getVulnerabilities() != null ? String.valueOf(result.getVulnerabilities().size()) : "0"));
        
        document.add(table);
    }
    
    private void addSecurityScore(Document document, ScanResult result) {
        BenchmarkComparator.BenchmarkComparison benchmark = BenchmarkComparator.compare(result);
        
        document.add(new Paragraph("Security Assessment")
            .setFontSize(18)
            .setBold()
            .setMarginTop(20));
        
        // Большой Security Score
        DeviceRgb color = benchmark.getOverallSecurityScore() >= 80 ? 
            new DeviceRgb(39, 174, 96) : // зеленый
            benchmark.getOverallSecurityScore() >= 60 ?
            new DeviceRgb(243, 156, 18) : // оранжевый
            new DeviceRgb(231, 76, 60);   // красный
        
        Paragraph scoreText = new Paragraph("Security Score: " + benchmark.getOverallSecurityScore() + "/100")
            .setFontSize(32)
            .setBold()
            .setFontColor(color)
            .setTextAlignment(TextAlignment.CENTER);
        document.add(scoreText);
        
        Paragraph rating = new Paragraph(benchmark.getOverallRating())
            .setFontSize(16)
            .setTextAlignment(TextAlignment.CENTER)
            .setMarginBottom(15);
        document.add(rating);
        
        // Детали
        Table details = new Table(2);
        details.setWidth(UnitValue.createPercentValue(100));
        details.addCell(createCell("Best Practice Score", benchmark.getBestPracticeScore() + "/100"));
        details.addCell(createCell("Уровень", benchmark.getBestPracticeLevel()));
        details.addCell(createCell("ГОСТ Compliance", benchmark.getGostComplianceScore() + "/100"));
        details.addCell(createCell("Уровень", benchmark.getGostComplianceLevel()));
        
        document.add(details);
    }
    
    private void addTopVulnerabilities(Document document, ScanResult result) {
        document.add(new Paragraph("Топ-10 критичных уязвимостей")
            .setFontSize(18)
            .setBold()
            .setMarginTop(20));
        
        String context = result.getExecutiveSummary() != null ? result.getExecutiveSummary().getApiContext() : null;
        java.util.List<Vulnerability> topCritical = ReportInsights.getTopCriticalVulnerabilities(result.getVulnerabilities(), context);

        if (topCritical.isEmpty()) {
            document.add(new Paragraph("Критичных уязвимостей не найдено")
                .setMarginBottom(10));
            return;
        }

        topCritical.stream()
            .limit(10)
            .forEach(vuln -> {
                DeviceRgb color = vuln.getSeverity() == Severity.CRITICAL ?
                    new DeviceRgb(231, 76, 60) :  // красный
                    new DeviceRgb(230, 126, 34);  // оранжевый
                
                String severityName = vuln.getSeverity() != null ? vuln.getSeverity().getRussianName() : "UNKNOWN";
                String title = vuln.getTitle() != null ? vuln.getTitle() : "Уязвимость";
                String endpoint = vuln.getEndpoint() != null ? vuln.getEndpoint() : "N/A";
                String method = vuln.getMethod() != null ? vuln.getMethod() : "N/A";
                String recommendation = vuln.getRecommendation() != null ? vuln.getRecommendation() : "Нет рекомендации";
                
                Paragraph vulnPara = new Paragraph()
                    .add(new Text(severityName)
                        .setFontColor(color)
                        .setBold())
                    .add(": " + title + "\n")
                    .add(new Text("Эндпоинт: ").setBold())
                    .add(endpoint + " [" + method + "]\n")
                    .add(new Text("Рекомендация: ").setBold())
                    .add(recommendation)
                    .setMarginBottom(10);
                
                document.add(vulnPara);
            });
    }
    
    private void addGostSection(Document document, ScanResult result) {
        // КРИТИЧНО: Защита от NPE
        long gostViolations = 0;
        if (result.getVulnerabilities() != null) {
            gostViolations = result.getVulnerabilities().stream()
                .filter(v -> v != null && v.isGostRelated())
                .count();
        }
        
        document.add(new Paragraph("ГОСТ Compliance")
            .setFontSize(18)
            .setBold()
            .setMarginTop(20));
        
        Paragraph gostText = new Paragraph()
            .add("Найдено нарушений ГОСТ стандартов: ")
            .add(new Text(String.valueOf(gostViolations)).setBold().setFontSize(16))
            .add("\n\nПроверка включала:\n")
            .add("• ГОСТ Р 34.10-2012 (Электронная подпись)\n")
            .add("• ГОСТ Р 34.11-2012 (Стрибог - хэш)\n")
            .add("• TLS cipher suites с ГОСТ\n")
            .add("• Сертификаты от российских УЦ\n")
            .add("• ФЗ-152 (персональные данные)");
        
        document.add(gostText);
    }
    
    private void addRecommendations(Document document, ScanResult result) {
        document.add(new Paragraph("Рекомендации")
            .setFontSize(18)
            .setBold()
            .setMarginTop(20));
        
        List list = new List()
            .setSymbolIndent(12)
            .setMarginLeft(20);
        
        // КРИТИЧНО: Защита от NPE
        if (result.hasCriticalVulnerabilities()) {
            list.add("НЕМЕДЛЕННО устраните CRITICAL уязвимости");
        }
        
        list.add("Добавьте аутентификацию для всех эндпоинтов с ID параметрами");
        list.add("Используйте параметризованные запросы для защиты от SQL injection");
        
        if (result.getVulnerabilities() != null) {
            long gostViolations = result.getVulnerabilities().stream()
                .filter(v -> v != null && v.isGostRelated())
                .count();
            if (gostViolations > 0) {
                list.add("Внедрите ГОСТ Р 34.10-2012 для соответствия российским стандартам");
            }
        }
        
        list.add("Настройте CI/CD интеграцию для автоматических проверок");
        
        document.add(list);
    }
    
    private Cell createCell(String label, String value) {
        Paragraph p = new Paragraph()
            .add(new Text(label + ": ").setBold())
            .add(value);
        return new Cell().add(p).setPadding(5);
    }
    
    @Override
    public String getFileExtension() {
        return "pdf";
    }
}

