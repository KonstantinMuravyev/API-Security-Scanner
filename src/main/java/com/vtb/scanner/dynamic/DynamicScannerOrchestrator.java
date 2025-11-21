package com.vtb.scanner.dynamic;

import com.vtb.scanner.config.ScannerConfig;
import com.vtb.scanner.dynamic.payload.PayloadBlueprint;
import com.vtb.scanner.dynamic.payload.PayloadFactory;
import com.vtb.scanner.models.AttackChainSummary;
import com.vtb.scanner.models.AttackSurfaceSummary;
import com.vtb.scanner.models.EntryPointSummary;
import com.vtb.scanner.semantic.ContextAnalyzer;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
public class DynamicScannerOrchestrator {

    public DynamicScanReport execute(String targetUrl,
                                     AttackSurfaceSummary attackSurface,
                                     ContextAnalyzer.APIContext context) {
        DynamicScannerSettings settings = new DynamicScannerSettings(ScannerConfig.load().getDynamicScanner());
        if (!settings.isEnabled()) {
            return DynamicScanReport.empty();
        }
        if (targetUrl == null || targetUrl.isBlank()) {
            return DynamicScanReport.empty();
        }
        List<PayloadBlueprint> payloadBlueprints = new PayloadFactory().build(attackSurface);
        List<ScenarioTrace> traces = buildTraces(targetUrl, attackSurface, settings);
        PayloadStats payloadStats = applyPayloadBlueprints(traces, payloadBlueprints);
        if (traces.isEmpty()) {
            return DynamicScanReport.empty();
        }

        TelemetryCollector telemetryCollector = new TelemetryCollector();
        ScenarioReplayer replayer = new ScenarioReplayer(settings, telemetryCollector);
        DynamicAnalyzer analyzer = new DynamicAnalyzer();

        List<DynamicFinding> findings = new ArrayList<>();
        int processed = 0;
        int executedSteps = 0;
        int maxScenarios = settings.maxScenarios();
        for (ScenarioTrace trace : traces) {
            if (maxScenarios > 0 && processed >= maxScenarios) {
                break;
            }
            processed++;
            ScenarioReplayResult replayResult = replayer.replay(targetUrl, trace);
            if (replayResult.getStepResults() != null) {
                executedSteps += replayResult.getStepResults().size();
            }
            TelemetrySummary summary = telemetryCollector.summarize();
            findings.addAll(analyzer.analyze(replayResult, summary));
        }

        List<String> notices = telemetryCollector.buildNotices();
        return DynamicScanReport.builder()
            .findings(findings)
            .telemetryNotices(notices)
            .executedScenarios(processed)
            .executedSteps(executedSteps)
            .payloadBlueprints(payloadStats != null ? payloadStats.totalBlueprints : 0)
            .payloadsMatched(payloadStats != null ? payloadStats.matchedBlueprints : 0)
            .appendedTraces(payloadStats != null ? payloadStats.appendedTraces : 0)
            .build();
    }

    private PayloadStats applyPayloadBlueprints(List<ScenarioTrace> traces,
                                                List<PayloadBlueprint> blueprints) {
        PayloadStats stats = new PayloadStats();
        if (blueprints == null) {
            return stats;
        }
        stats.totalBlueprints = blueprints.size();
        if (traces == null || blueprints.isEmpty()) {
            return stats;
        }
        Map<String, PayloadBlueprint> blueprintMap = new LinkedHashMap<>();
        for (PayloadBlueprint blueprint : blueprints) {
            if (blueprint == null || blueprint.getMethod() == null || blueprint.getPath() == null) {
                continue;
            }
            String normalizedPath = normalizePath(blueprint.getPath());
            if (normalizedPath == null) {
                continue;
            }
            String key = blueprintKey(blueprint.getMethod(), normalizedPath);
            blueprintMap.putIfAbsent(key, blueprint);
        }

        Set<String> matchedBlueprints = new HashSet<>();
        for (ScenarioTrace trace : traces) {
            if (trace == null || trace.getSteps() == null) {
                continue;
            }
            for (ScenarioStep step : trace.getSteps()) {
                PayloadBlueprint blueprint = matchBlueprint(step, blueprintMap);
                if (blueprint != null) {
                    decorateStepWithBlueprint(step, blueprint);
                    matchedBlueprints.add(blueprint.getId());
                }
            }
        }

        for (PayloadBlueprint blueprint : blueprints) {
            if (blueprint == null || blueprint.getId() == null) {
                continue;
            }
            if (matchedBlueprints.contains(blueprint.getId())) {
                continue;
            }
            String normalizedPath = normalizePath(blueprint.getPath());
            if (normalizedPath == null) {
                continue;
            }
            ScenarioStep step = ScenarioStep.builder()
                .method(blueprint.getMethod() != null ? blueprint.getMethod() : "GET")
                .path(normalizedPath)
                .headers(new LinkedHashMap<>(blueprint.getHeaders()))
                .body(blueprint.getBody())
                .expectedStatus(blueprint.getExpectedStatus())
                .shouldEnforceAuth(blueprint.isEnforceAuth())
                .description(blueprint.getDescription())
                .build();
            ScenarioTrace trace = ScenarioTrace.builder()
                .id("payload-" + blueprint.getId())
                .name("Payload probe: " + blueprint.getType())
                .source("PayloadFactory")
                .steps(List.of(step))
                .maxSteps(1)
                .build();
            traces.add(trace);
            stats.appendedTraces++;
        }
        stats.matchedBlueprints = matchedBlueprints.size();
        return stats;
    }

    private PayloadBlueprint matchBlueprint(ScenarioStep step,
                                            Map<String, PayloadBlueprint> blueprintMap) {
        if (step == null || blueprintMap.isEmpty()) {
            return null;
        }
        String method = step.getMethod() != null ? step.getMethod().toUpperCase(Locale.ROOT) : "GET";
        String normalizedPath = normalizePath(step.getPath());
        if (normalizedPath == null) {
            return null;
        }
        return blueprintMap.get(blueprintKey(method, normalizedPath));
    }

    private void decorateStepWithBlueprint(ScenarioStep step, PayloadBlueprint blueprint) {
        if (blueprint.getHeaders() != null && !blueprint.getHeaders().isEmpty()) {
            if (step.getHeaders() == null) {
                step.setHeaders(new LinkedHashMap<>());
            }
            step.getHeaders().putAll(blueprint.getHeaders());
        }
        if (blueprint.getBody() != null) {
            step.setBody(blueprint.getBody());
        }
        if (blueprint.getExpectedStatus() != null) {
            step.setExpectedStatus(blueprint.getExpectedStatus());
        }
        if (blueprint.isEnforceAuth()) {
            step.setShouldEnforceAuth(true);
        }
        if (blueprint.getDescription() != null && !blueprint.getDescription().isBlank()) {
            if (step.getDescription() == null || step.getDescription().isBlank()) {
                step.setDescription(blueprint.getDescription());
            } else if (!step.getDescription().contains(blueprint.getDescription())) {
                step.setDescription(step.getDescription() + " | " + blueprint.getDescription());
            }
        }
    }

    private String blueprintKey(String method, String path) {
        String normalizedMethod = method != null ? method.toUpperCase(Locale.ROOT) : "GET";
        String normalizedPath = normalizePath(path);
        if (normalizedPath == null) {
            return null;
        }
        return normalizedMethod + " " + normalizedPath;
    }

    private static class PayloadStats {
        int totalBlueprints = 0;
        int matchedBlueprints = 0;
        int appendedTraces = 0;
    }

    private List<ScenarioTrace> buildTraces(String targetUrl,
                                            AttackSurfaceSummary attackSurface,
                                            DynamicScannerSettings settings) {
        List<ScenarioTrace> traces = new ArrayList<>();
        if (attackSurface == null) {
            return traces;
        }

        List<EntryPointSummary> entryPoints = attackSurface.getEntryPointDetails();
        if ((entryPoints == null || entryPoints.isEmpty()) && attackSurface.getEntryPoints() != null) {
            entryPoints = attackSurface.getEntryPoints().stream()
                .map(this::fallbackEntryPoint)
                .collect(Collectors.toList());
        }

        if (entryPoints != null) {
            entryPoints.stream()
                .sorted(Comparator.comparingInt(EntryPointSummary::getRiskScore).reversed())
                .forEach(entry -> {
                    ScenarioStep step = ScenarioStep.builder()
                        .method(entry.getMethod() != null ? entry.getMethod() : "GET")
                        .path(normalizePath(entry.getPath()))
                        .shouldEnforceAuth(entry.isWeakProtection())
                        .description("Dynamic replay for entry point")
                        .build();
                    ScenarioTrace trace = ScenarioTrace.builder()
                        .id("entry-" + entry.getKey())
                        .name("Entry point check " + entry.getKey())
                        .source("AttackSurfaceGraph")
                        .steps(List.of(step))
                        .maxSteps(1)
                        .build();
                    traces.add(trace);
                });
        }

        addAttackChainTraces(traces, attackSurface);
        return traces;
    }

    private void addAttackChainTraces(List<ScenarioTrace> traces, AttackSurfaceSummary attackSurface) {
        if (attackSurface == null || attackSurface.getAttackChains() == null) {
            return;
        }
        int index = 0;
        for (AttackChainSummary chain : attackSurface.getAttackChains()) {
            List<ScenarioStep> steps = buildStepsForChain(chain);
            if (steps.isEmpty()) {
                continue;
            }
            String chainId = "chain-" + (++index);
            ScenarioTrace trace = ScenarioTrace.builder()
                .id(chainId)
                .name("Attack chain " + chain.getType() + " → " + safeTargetLabel(chain.getTarget()))
                .source("AttackChain")
                .steps(steps)
                .maxSteps(Math.max(steps.size(), 1))
                .build();
            traces.add(trace);
        }
    }

    private EntryPointSummary fallbackEntryPoint(String entry) {
        String method = "GET";
        String path = entry;
        if (entry != null && entry.contains(" ")) {
            String[] parts = entry.split(" ", 2);
            method = parts[0];
            path = parts[1];
        }
        return EntryPointSummary.builder()
            .key(entry)
            .method(method)
            .path(path)
            .severity("HIGH")
            .riskScore(120)
            .weakProtection(true)
            .build();
    }

    private List<ScenarioStep> buildStepsForChain(AttackChainSummary chain) {
        List<ScenarioStep> steps = new ArrayList<>();
        if (chain == null) {
            return steps;
        }
        String type = chain.getType() != null ? chain.getType().toUpperCase(Locale.ROOT) : "";
        Map<String, String> metadata = chain.getMetadata();

        switch (type) {
            case "ENTRY_POINT" -> {
                MethodPathSignature sig = parseSignature(chain.getTarget());
                if (sig != null) {
                    steps.add(buildStep(sig.method(), sig.path(), true,
                        "Entry point chain replay (expected auth required)"));
                }
            }
            case "LIST_TO_RESOURCE", "BOLA" -> {
                String listEndpoint = metadata != null ? metadata.get("listEndpoint") : null;
                if (listEndpoint != null && !listEndpoint.isBlank()) {
                    boolean listProtected = Boolean.parseBoolean(
                        metadata.getOrDefault("listProtected", "false"));
                    steps.add(buildStep("GET", listEndpoint, listProtected,
                        "Enumerate collection for chain"));
                }
                MethodPathSignature target = parseSignature(chain.getTarget());
                if (target != null) {
                    steps.add(buildStep(target.method(), target.path(), true,
                        "Attempt resource access without auth"));
                }
            }
            default -> {
                MethodPathSignature fallback = parseSignature(chain.getTarget());
                if (fallback != null) {
                    steps.add(buildStep(fallback.method(), fallback.path(), true,
                        "Replay chain target"));
                }
            }
        }
        return steps.stream()
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    }

    private ScenarioStep buildStep(String method, String path, boolean enforceAuth, String description) {
        String normalizedPath = normalizePath(path);
        if (normalizedPath == null) {
            return null;
        }
        return ScenarioStep.builder()
            .method(method != null ? method : "GET")
            .path(normalizedPath)
            .shouldEnforceAuth(enforceAuth)
            .description(description)
            .build();
    }

    private String normalizePath(String path) {
        if (path == null) {
            return null;
        }
        String trimmed = path.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            return trimmed;
        }
        if (!trimmed.startsWith("/")) {
            return "/" + trimmed.replaceFirst("^\\./", "");
        }
        return trimmed;
    }

    private MethodPathSignature parseSignature(String signature) {
        if (signature == null) {
            return null;
        }
        String trimmed = signature.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        String method = "GET";
        String path = trimmed;
        int spaceIdx = trimmed.indexOf(' ');
        if (spaceIdx > 0) {
            method = trimmed.substring(0, spaceIdx).trim();
            path = trimmed.substring(spaceIdx + 1).trim();
        }
        return new MethodPathSignature(method.isEmpty() ? "GET" : method, path);
    }

    private String safeTargetLabel(String target) {
        if (target == null || target.isBlank()) {
            return "unknown";
        }
        return target.length() > 40 ? target.substring(0, 40) + "…" : target;
    }

    private record MethodPathSignature(String method, String path) {}
}
