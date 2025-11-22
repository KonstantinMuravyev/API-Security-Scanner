package com.vtb.scanner.reports;

import com.vtb.scanner.analysis.AttackSurfaceMapper;
import com.vtb.scanner.semantic.ContextAnalyzer;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.Collections;
import java.util.List;

/**
 * Генератор отчета по Attack Surface
 */
@Slf4j
public class AttackSurfaceReportGenerator {
    
    public void generate(AttackSurfaceMapper.AttackSurface surface, Path outputPath) throws IOException {
        log.info("Генерация Attack Surface Report: {}", outputPath);
        
        // КРИТИЧНО: Защита от NPE
        if (surface == null) {
            throw new IllegalArgumentException("AttackSurface не может быть null");
        }
        
        StringBuilder html = new StringBuilder();
        
        String contextBadge = buildContextBadge(surface.getContext());

        html.append("""
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <title>Attack Surface Map</title>
                <style>
                    body { font-family: Arial, sans-serif; padding: 20px; background: #f5f5f5; }
                    .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
                    h1 { color: #e74c3c; }
                    .stat { display: inline-block; margin: 10px 20px; padding: 15px; background: #ecf0f1; border-radius: 5px; }
                    .stat-number { font-size: 32px; font-weight: bold; color: #2c3e50; }
                    .stat-label { font-size: 14px; color: #7f8c8d; }
                    .entry-point { background: #ffe6e6; padding: 10px; margin: 5px 0; border-left: 4px solid #e74c3c; }
                    .attack-chain { background: #fff3cd; padding: 15px; margin: 10px 0; border-left: 4px solid #ffc107; }
                    .chain-step { padding: 5px 0; margin-left: 20px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🗺️ Attack Surface Map</h1>
                    <p>Карта поверхности атаки API - критичные точки и цепочки эксплуатации</p>
                    %s
                    
                    <div class="stats">
                        <div class="stat">
                            <div class="stat-number">%d</div>
                            <div class="stat-label">Всего эндпоинтов</div>
                        </div>
                        <div class="stat">
                            <div class="stat-number">%d</div>
                            <div class="stat-label">Точек входа (без auth)</div>
                        </div>
                        <div class="stat">
                            <div class="stat-number">%d</div>
                            <div class="stat-label">Цепочек атак</div>
                        </div>
                    </div>
                    
                    <h2>🚪 Точки входа (Entry Points)</h2>
                    <p>Эндпоинты без аутентификации - потенциальные точки атаки:</p>
            """.formatted(
                contextBadge,
                surface.getNodes() != null ? surface.getNodes().size() : 0,
                surface.getEntryPoints() != null ? surface.getEntryPoints().size() : 0,
                surface.getAttackChains() != null ? surface.getAttackChains().size() : 0
            ));
        
        // Entry points
        List<AttackSurfaceMapper.EntryPoint> entryPointDetails = surface.getEntryPointDetails() != null
            ? surface.getEntryPointDetails()
            : Collections.emptyList();
        if (!entryPointDetails.isEmpty()) {
            for (AttackSurfaceMapper.EntryPoint entryPoint : entryPointDetails) {
                if (entryPoint == null) {
                    continue;
                }
                String label = entryPoint.getKey() != null ? entryPoint.getKey() : entryPoint.getPath();
                html.append("<div class=\"entry-point\">🔓 ")
                    .append(escapeHtml(label != null ? label : "Endpoint"))
                    .append(" <span style=\"font-size:12px; color:#c0392b; font-weight:600;\">Risk: ")
                    .append(entryPoint.getRiskScore())
                    .append("</span>");
                if (entryPoint.getDataSensitivityLevel() != null && !entryPoint.getDataSensitivityLevel().isBlank()) {
                    html.append(" · <span style=\"font-size:12px; color:#8e44ad;\">PII: ")
                        .append(escapeHtml(entryPoint.getDataSensitivityLevel().toUpperCase(Locale.ROOT)))
                        .append("</span>");
                }
                if (entryPoint.getSignals() != null && !entryPoint.getSignals().isEmpty()) {
                    html.append("<br><span style=\"font-size:12px; color:#34495e;\">Signals: ")
                        .append(escapeHtml(String.join(", ", entryPoint.getSignals())))
                        .append("</span>");
                }
                html.append("</div>\n");
            }
        } else if (surface.getEntryPoints() != null) {
            for (String entryPoint : surface.getEntryPoints()) {
                if (entryPoint != null) {
                    html.append(String.format(
                        "<div class=\"entry-point\">🔓 %s</div>\n",
                        entryPoint
                    ));
                }
            }
        }
        
        // Attack chains
        html.append("""
            
            <h2>Цепочки атак (Attack Chains)</h2>
            <p>Последовательности действий для эксплуатации уязвимостей:</p>
            """);
        
        if (surface.getAttackChains() != null) {
            for (AttackSurfaceMapper.AttackChain chain : surface.getAttackChains()) {
                if (chain == null) continue;
                
                String target = chain.getTarget() != null ? chain.getTarget() : "N/A";
                String severity = chain.getSeverity() != null ? chain.getSeverity() : "UNKNOWN";
                String severityColor = colorForSeverity(severity);
                String type = chain.getType() != null ? chain.getType() : "ATTACK_CHAIN";
                
                html.append(String.format(
                    "<div class=\"attack-chain\">\n" +
                    "<strong>Тип:</strong> %s %s<br>\n" +
                    "<strong>Цель:</strong> %s<br>\n" +
                    "<strong>Серьезность:</strong> <span style=\"color: %s; font-weight: 600;\">%s</span><br>\n",
                    escapeHtml(type),
                    buildExploitableBadge(chain),
                    escapeHtml(target),
                    severityColor,
                    escapeHtml(severity)
                ));

                html.append(buildSensitivityBlock(chain));
                html.append(buildMetadataBlock(chain.getMetadata()));
                
                if (chain.getSteps() != null) {
                    html.append("<strong>Шаги:</strong>\n");
                    for (String step : chain.getSteps()) {
                        if (step != null) {
                            html.append(String.format(
                                "<div class=\"chain-step\">%s</div>\n",
                                escapeHtml(step)
                            ));
                        }
                    }
                }
                
                html.append("</div>\n");
            }
        }
        
        html.append("""
                </div>
            </body>
            </html>
            """);
        
        Files.writeString(outputPath, html.toString());
        log.info("Attack Surface Report сохранен: {}", outputPath);
    }

    private String buildContextBadge(String context) {
        if (context == null || context.isBlank()) {
            return "";
        }
        String label = context;
        try {
            ContextAnalyzer.APIContext apiContext = ContextAnalyzer.APIContext.valueOf(context);
            label = apiContext.getDescription();
        } catch (IllegalArgumentException ignored) {
            label = context.toUpperCase(Locale.ROOT);
        }
        return "<div style=\"margin: 12px 0 4px 0;\"><span style=\"display:inline-flex;align-items:center;gap:8px;background:rgba(231,76,60,0.1);color:#c0392b;padding:6px 14px;border-radius:999px;font-size:13px;font-weight:600;letter-spacing:0.4px;text-transform:uppercase;\">Контекст: " + escapeHtml(label) + "</span></div>";
    }

    private String colorForSeverity(String severity) {
        if (severity == null) {
            return "#7f8c8d";
        }
        return switch (severity.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> "#e74c3c";
            case "HIGH" -> "#e67e22";
            case "MEDIUM" -> "#f39c12";
            case "LOW" -> "#3498db";
            default -> "#7f8c8d";
        };
    }

    private String buildExploitableBadge(AttackSurfaceMapper.AttackChain chain) {
        if (chain != null && chain.isExploitable()) {
            return "<span style=\"background:#fdecea;color:#c0392b;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;margin-left:8px;\">🔥 EXPLOITABLE</span>";
        }
        return "";
    }

    private String buildSensitivityBlock(AttackSurfaceMapper.AttackChain chain) {
        if (chain == null || chain.getDataSensitivityLevel() == null || chain.getDataSensitivityLevel().isBlank()) {
            return "";
        }
        String color = colorForSeverity(chain.getDataSensitivityLevel());
        StringBuilder builder = new StringBuilder();
        builder.append("<div style=\"margin-top:6px;font-size:13px;color:#2c3e50;\">")
            .append("<strong>Data Sensitivity:</strong> ")
            .append("<span style=\"color:").append(color).append(";font-weight:600;\">")
            .append(escapeHtml(chain.getDataSensitivityLevel().toUpperCase(Locale.ROOT))).append("</span>");
        if (chain.getSensitiveFields() != null && !chain.getSensitiveFields().isEmpty()) {
            builder.append("<div style=\"margin-top:4px;color:#555;\">")
                .append(escapeHtml(String.join(", ", chain.getSensitiveFields())))
                .append("</div>");
        }
        builder.append("</div>");
        return builder.toString();
    }

    private String buildMetadataBlock(Map<String, String> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return "";
        }
        StringBuilder builder = new StringBuilder("<div style=\"margin-top:6px;font-size:12px;color:#555;\">");
        for (Map.Entry<String, String> entry : metadata.entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            builder.append("<div><strong>")
                .append(escapeHtml(humanize(entry.getKey())))
                .append(":</strong> ")
                .append(escapeHtml(entry.getValue()))
                .append("</div>");
        }
        builder.append("</div>");
        return builder.toString();
    }

    private String humanize(String key) {
        if (key == null) {
            return "";
        }
        return switch (key) {
            case "listEndpoint" -> "Список (endpoint)";
            case "listHasAuth" -> "Аутентификация на списке";
            case "resourceHasAuth" -> "Аутентификация на ресурсе";
            default -> key.replace("_", " ").replace("-", " ").trim();
        };
    }

    private String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#39;");
    }
}

