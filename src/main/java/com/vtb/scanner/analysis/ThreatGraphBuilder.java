package com.vtb.scanner.analysis;

import com.vtb.scanner.models.AttackChainSummary;
import com.vtb.scanner.models.AttackSurfaceSummary;
import com.vtb.scanner.models.DataProtectionSummary;
import com.vtb.scanner.models.PiiExposure;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.ThreatEdge;
import com.vtb.scanner.models.ThreatGraph;
import com.vtb.scanner.models.ThreatNode;
import com.vtb.scanner.models.ThreatPath;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.semantic.ContextAnalyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public final class ThreatGraphBuilder {

    private ThreatGraphBuilder() {}

    public static ThreatGraph build(List<Vulnerability> vulnerabilities,
                                    AttackSurfaceSummary attackSurface,
                                    DataProtectionSummary dataProtection,
                                    ContextAnalyzer.APIContext context) {
        Map<String, ThreatNode> nodeMap = new LinkedHashMap<>();
        List<ThreatEdge> edges = new ArrayList<>();
        List<ThreatPath> paths = new ArrayList<>();
        Map<Vulnerability, String> vulnerabilityNodeIds = new IdentityHashMap<>();
        Map<String, String> vulnerabilityIdToNode = new LinkedHashMap<>();
        Map<String, List<Vulnerability>> vulnerabilitiesByEndpoint = new LinkedHashMap<>();

        ContextAnalyzer.APIContext effectiveContext = context != null ? context : ContextAnalyzer.APIContext.GENERAL;
        double entryBaseScore = switch (effectiveContext) {
            case BANKING -> 3.5;
            case TELECOM -> 3.2;
            case GOVERNMENT -> 3.4;
            default -> 3.0;
        };

        Map<String, String> entryPointMap = new LinkedHashMap<>();
        List<String> entryPoints = attackSurface != null ? attackSurface.getEntryPoints() : Collections.emptyList();
        for (String entry : Optional.ofNullable(entryPoints).orElse(Collections.emptyList())) {
            String nodeId = "ENTRY:" + entry;
            ThreatNode node = ThreatNode.builder()
                .id(nodeId)
                .type("ENTRY_POINT")
                .label(entry)
                .severity(Severity.HIGH)
                .score(entryBaseScore)
                .build();
            nodeMap.putIfAbsent(nodeId, node);
            entryPointMap.put(normalizeKey(entry), nodeId);
        }

        Map<String, String> endpointNodes = new LinkedHashMap<>();

        for (Vulnerability vulnerability : Optional.ofNullable(vulnerabilities).orElse(Collections.emptyList())) {
            if (vulnerability == null) {
                continue;
            }

            String method = Optional.ofNullable(vulnerability.getMethod()).orElse("N/A").toUpperCase(Locale.ROOT);
            String endpoint = Optional.ofNullable(vulnerability.getEndpoint()).orElse("N/A");
            if ("N/A".equals(endpoint)) {
                continue;
            }

            String endpointKey = normalizeKey(method + " " + endpoint);
            String endpointNodeId = endpointNodes.computeIfAbsent(endpointKey, key -> {
                Severity effectiveSeverity = Optional.ofNullable(vulnerability.getSeverity()).orElse(Severity.MEDIUM);
                ThreatNode node = ThreatNode.builder()
                    .id("ENDPOINT:" + key)
                    .type("ENDPOINT")
                    .label(method + " " + endpoint)
                    .severity(effectiveSeverity)
                    .score(severityScore(effectiveSeverity))
                    .build();
                nodeMap.put(node.getId(), node);
                return node.getId();
            });

            ThreatNode endpointNode = nodeMap.get(endpointNodeId);
            Severity vulnSeverity = Optional.ofNullable(vulnerability.getSeverity()).orElse(Severity.MEDIUM);
            double candidateScore = severityScore(vulnSeverity);
            if (candidateScore > endpointNode.getScore()) {
                endpointNode.setSeverity(vulnSeverity);
                endpointNode.setScore(candidateScore);
            }
            String signalTitle = Optional.ofNullable(vulnerability.getTitle()).orElse("Без названия");
            endpointNode.getSignals().add(signalTitle);
            endpointNode.getMetadata().put("riskScore", String.valueOf(vulnerability.getRiskScore()));

            String vulnId = Optional.ofNullable(vulnerability.getId())
                .filter(id -> !id.isBlank())
                .orElse("AUTO-" + Math.abs(Objects.hash(signalTitle, endpointKey)));
            String typeName = vulnerability.getType() != null ? vulnerability.getType().name() : "UNKNOWN";
            String vulnNodeId = "VULN:" + vulnId;
            ThreatNode vulnNode = ThreatNode.builder()
                .id(vulnNodeId)
                .type("VULNERABILITY")
                .label(signalTitle)
                .severity(vulnSeverity)
                .score(candidateScore)
                .metadata(buildVulnerabilityMetadata(typeName, vulnerability.getImpactLevel(), endpoint))
                .build();
            nodeMap.put(vulnNodeId, vulnNode);
            vulnerabilityNodeIds.put(vulnerability, vulnNodeId);
            vulnerabilityIdToNode.put(normalize(vulnId), vulnNodeId);
            vulnerabilitiesByEndpoint.computeIfAbsent(endpointNodeId, k -> new ArrayList<>()).add(vulnerability);

            edges.add(ThreatEdge.builder()
                .from(endpointNodeId)
                .to(vulnNodeId)
                .type("HAS_VULNERABILITY")
                .label(typeName)
                .build());

            String entryNodeId = entryPointMap.get(endpointKey);
            if (entryNodeId != null) {
                edges.add(ThreatEdge.builder()
                    .from(entryNodeId)
                    .to(endpointNodeId)
                    .type("REACHES")
                    .label("entry")
                    .build());
            }
        }

        List<AttackChainSummary> chains = attackSurface != null ? attackSurface.getAttackChains() : Collections.emptyList();
        int chainIndex = 0;
        for (AttackChainSummary chain : Optional.ofNullable(chains).orElse(Collections.emptyList())) {
            String target = Optional.ofNullable(chain.getTarget()).orElse("target-" + chainIndex);
            String chainNodeId = "CHAIN:" + chainIndex;
            Severity chainSeverity = parseSeverity(chain.getSeverity());
            ThreatNode chainNode = ThreatNode.builder()
                .id(chainNodeId)
                .type("ATTACK_CHAIN")
                .label("Attack Chain → " + target)
                .severity(chainSeverity)
                .score(severityScore(chainSeverity) + (chain.isExploitable() ? 1.5 : 0))
                .metadata(buildChainMetadata(chain))
                .build();
            nodeMap.put(chainNodeId, chainNode);

            String normalizedTarget = normalizeKey(target);
            String endpointNodeId = endpointNodes.get(normalizedTarget);
            if (endpointNodeId == null) {
                endpointNodeId = endpointNodes.computeIfAbsent(normalizedTarget, key -> {
                    ThreatNode node = ThreatNode.builder()
                        .id("ENDPOINT:" + key)
                        .type("ENDPOINT")
                        .label(target)
                        .severity(chainSeverity)
                        .score(severityScore(chainSeverity))
                        .build();
                    nodeMap.put(node.getId(), node);
                    return node.getId();
                });
            }

            edges.add(ThreatEdge.builder()
                .from(endpointNodeId)
                .to(chainNodeId)
                .type("PART_OF_CHAIN")
                .label("chain")
                .build());

            Optional.ofNullable(chain.getSensitiveFields()).orElse(Collections.emptyList())
                .forEach(field -> nodeMap.get(chainNodeId).getSignals().add("sensitive:" + field));

            ThreatPath path = ThreatPath.builder()
                .name("Chain " + (++chainIndex))
                .severity(chainSeverity)
                .score(chainNode.getScore())
                .nodeIds(buildPathNodeIds(entryPointMap, endpointNodeId, chainNodeId))
                .steps(Optional.ofNullable(chain.getSteps()).orElse(Collections.emptyList()))
                .description(buildPathDescription(chain))
                .build();
            paths.add(path);
        }

        addCorrelatedRisks(vulnerabilitiesByEndpoint,
            vulnerabilityNodeIds,
            nodeMap,
            edges,
            paths,
            entryPointMap,
            effectiveContext);

        addDataProtectionNodes(dataProtection,
            endpointNodes,
            vulnerabilityIdToNode,
            nodeMap,
            edges,
            paths,
            entryPointMap);

        double maxScore = nodeMap.values().stream()
            .mapToDouble(ThreatNode::getScore)
            .max()
            .orElse(0);
        double avgScore = nodeMap.values().stream()
            .mapToDouble(ThreatNode::getScore)
            .average()
            .orElse(0);

        paths.sort(Comparator.comparingDouble(ThreatPath::getScore).reversed());
        if (paths.size() > 10) {
            paths = new ArrayList<>(paths.subList(0, 10));
        }

        return ThreatGraph.builder()
            .nodes(new ArrayList<>(nodeMap.values()))
            .edges(edges)
            .criticalPaths(paths)
            .maxScore(maxScore)
            .averageScore(avgScore)
            .build();
    }

    private static String normalizeKey(String value) {
        if (value == null) {
            return "N/A";
        }
        return value.trim().toUpperCase(Locale.ROOT);
    }

    private static double severityScore(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 4.0;
            case HIGH -> 3.0;
            case MEDIUM -> 2.0;
            case LOW -> 1.0;
            default -> 0.5;
        };
    }

    private static Severity parseSeverity(String severity) {
        if (severity == null) {
            return Severity.MEDIUM;
        }
        try {
            return Severity.valueOf(severity.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return Severity.MEDIUM;
        }
    }

    private static Map<String, String> buildChainMetadata(AttackChainSummary chain) {
        Map<String, String> metadata = new LinkedHashMap<>();
        if (chain.getDataSensitivityLevel() != null) {
            metadata.put("sensitivity", chain.getDataSensitivityLevel());
        }
        metadata.put("exploitable", String.valueOf(chain.isExploitable()));
        if (!chain.getSensitiveFields().isEmpty()) {
            metadata.put("fields", String.join(", ", chain.getSensitiveFields()));
        }
        return metadata;
    }

    private static Map<String, String> buildVulnerabilityMetadata(String type,
                                                                  String impactLevel,
                                                                  String endpoint) {
        Map<String, String> metadata = new LinkedHashMap<>();
        metadata.put("type", Optional.ofNullable(type).orElse("UNKNOWN"));
        if (impactLevel != null && !impactLevel.isBlank()) {
            metadata.put("impact", impactLevel);
        }
        metadata.put("endpoint", Optional.ofNullable(endpoint).orElse(""));
        return metadata;
    }

    private static void addCorrelatedRisks(Map<String, List<Vulnerability>> vulnerabilitiesByEndpoint,
                                           Map<Vulnerability, String> vulnerabilityNodeIds,
                                           Map<String, ThreatNode> nodeMap,
                                           List<ThreatEdge> edges,
                                           List<ThreatPath> paths,
                                           Map<String, String> entryPointMap,
                                           ContextAnalyzer.APIContext context) {
        if (vulnerabilitiesByEndpoint.isEmpty()) {
            return;
        }

        for (Map.Entry<String, List<Vulnerability>> entry : vulnerabilitiesByEndpoint.entrySet()) {
            String endpointNodeId = entry.getKey();
            ThreatNode endpointNode = nodeMap.get(endpointNodeId);
            if (endpointNode == null) {
                continue;
            }

            List<Vulnerability> vulnerabilityList = entry.getValue();
            Set<VulnerabilityType> types = vulnerabilityList.stream()
                .map(Vulnerability::getType)
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(VulnerabilityType.class)));

            if (types.isEmpty()) {
                continue;
            }

            List<CorrelatedRisk> correlatedRisks = detectCorrelatedRisks(types, endpointNode, context);
            for (CorrelatedRisk risk : correlatedRisks) {
                String riskNodeId = "CORR:" + endpointNodeId + ":" + risk.key();
                if (nodeMap.containsKey(riskNodeId)) {
                    continue;
                }

                ThreatNode riskNode = ThreatNode.builder()
                    .id(riskNodeId)
                    .type("CORRELATED_RISK")
                    .label(risk.label())
                    .severity(risk.severity())
                    .score(severityScore(risk.severity()) + risk.scoreBoost())
                    .signals(new ArrayList<>(risk.signals()))
                    .metadata(new LinkedHashMap<>(Map.of(
                        "pattern", risk.key(),
                        "endpoint", endpointNode.getLabel())))
                    .build();
                nodeMap.put(riskNodeId, riskNode);

                edges.add(ThreatEdge.builder()
                    .from(endpointNodeId)
                    .to(riskNodeId)
                    .type("CORRELATION")
                    .label(risk.key())
                    .build());

                for (Vulnerability correlatedVuln : vulnerabilityList) {
                    if (risk.types().contains(correlatedVuln.getType())) {
                        String vulnNodeId = vulnerabilityNodeIds.get(correlatedVuln);
                        if (vulnNodeId != null && nodeMap.containsKey(vulnNodeId)) {
                            edges.add(ThreatEdge.builder()
                                .from(riskNodeId)
                                .to(vulnNodeId)
                                .type("SUPPORTED_BY")
                                .label(correlatedVuln.getType().name())
                                .build());
                        }
                    }
                }

                ThreatPath path = ThreatPath.builder()
                    .name(risk.label())
                    .severity(risk.severity())
                    .score(riskNode.getScore())
                    .nodeIds(buildPathNodeIds(entryPointMap, endpointNodeId, riskNodeId))
                    .steps(risk.steps())
                    .description(risk.description())
                    .build();
                paths.add(path);
            }
        }
    }

    private static List<String> buildPathNodeIds(Map<String, String> entryPointMap,
                                                 String endpointNodeId,
                                                 String targetNodeId) {
        List<String> nodeIds = new ArrayList<>();
        Set<String> matchingEntries = entryPointMap.entrySet().stream()
            .filter(e -> endpointNodeId.endsWith(e.getKey()))
            .map(Map.Entry::getValue)
            .collect(Collectors.toCollection(LinkedHashSet::new));
        nodeIds.addAll(matchingEntries);
        nodeIds.add(endpointNodeId);
        nodeIds.add(targetNodeId);
        return nodeIds;
    }

    private static Severity adjustSeverity(Severity base, ContextAnalyzer.APIContext context) {
        if (base == null) {
            base = Severity.MEDIUM;
        }
        if (context == null) {
            return base;
        }
        return switch (context) {
            case BANKING, HEALTHCARE, GOVERNMENT -> elevate(base);
            default -> base;
        };
    }

    private static Severity elevate(Severity base) {
        return switch (base) {
            case CRITICAL -> Severity.CRITICAL;
            case HIGH -> Severity.CRITICAL;
            case MEDIUM -> Severity.HIGH;
            case LOW -> Severity.MEDIUM;
            default -> Severity.MEDIUM;
        };
    }

    private static List<CorrelatedRisk> detectCorrelatedRisks(Set<VulnerabilityType> types,
                                                              ThreatNode endpointNode,
                                                              ContextAnalyzer.APIContext context) {
        List<CorrelatedRisk> risks = new ArrayList<>();
        String endpointLabel = endpointNode.getLabel() != null ? endpointNode.getLabel() : "endpoint";
        Severity basePrivilegeSeverity = adjustSeverity(Severity.CRITICAL, context);

        if (containsAny(types, VulnerabilityType.BOLA, VulnerabilityType.BFLA, VulnerabilityType.BROKEN_AUTHENTICATION)
            && containsAny(types, VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW,
            VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION,
            VulnerabilityType.RATE_LIMIT_MISSING)) {
            risks.add(new CorrelatedRisk(
                "PRIVILEGE_ESCALATION",
                "Privilege Escalation Chain (" + endpointLabel + ")",
                basePrivilegeSeverity,
                List.of("BOLA/BFLA", "RateLimit/BusinessFlow"),
                List.of("Доступ к объекту", "Отсутствие ограничений", "Эскалация привилегий"),
                "Комбинация недостатков авторизации и отсутствия ограничений позволяет атакующему " +
                    "пройти бизнес-флоу без контроля и захватить чужие ресурсы.",
                EnumSet.of(VulnerabilityType.BOLA, VulnerabilityType.BFLA, VulnerabilityType.BROKEN_AUTHENTICATION,
                    VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW, VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION,
                    VulnerabilityType.RATE_LIMIT_MISSING),
                0.8));
        }

        if (types.contains(VulnerabilityType.SSRF)
            && containsAny(types, VulnerabilityType.SECURITY_MISCONFIGURATION,
            VulnerabilityType.CORS_MISCONFIGURATION, VulnerabilityType.DEBUG_ENDPOINT)) {
            Severity severity = adjustSeverity(Severity.HIGH, context);
            risks.add(new CorrelatedRisk(
                "SSRF_PIVOT",
                "SSRF Pivot Risk (" + endpointLabel + ")",
                severity,
                List.of("SSRF", "Misconfiguration"),
                List.of("Бэкэнд запрос", "Конфигурация", "Потенциальный летающий коридор"),
                "Endpoint принимает внешние URL и допускает SSRF, а конфигурация сервера позволяет проксировать " +
                    "запросы внутрь инфраструктуры.",
                EnumSet.of(VulnerabilityType.SSRF, VulnerabilityType.SECURITY_MISCONFIGURATION,
                    VulnerabilityType.CORS_MISCONFIGURATION, VulnerabilityType.DEBUG_ENDPOINT),
                0.6));
        }

        if (containsAny(types, VulnerabilityType.SQL_INJECTION, VulnerabilityType.NOSQL_INJECTION,
            VulnerabilityType.COMMAND_INJECTION, VulnerabilityType.LDAP_INJECTION)
            && containsAny(types, VulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
            VulnerabilityType.SENSITIVE_DATA_IN_URL)) {
            Severity severity = adjustSeverity(Severity.CRITICAL, context);
            risks.add(new CorrelatedRisk(
                "DATA_EXFILTRATION",
                "Data Exfiltration Chain (" + endpointLabel + ")",
                severity,
                List.of("Injection", "Data Exposure"),
                List.of("Инъекционная атака", "Утечка данных", "Экфильтрация чувствительных данных"),
                "Injection уязвимость в сочетании с избыточной выдачей данных создаёт прямой риск утечки " +
                    "персональной и финансовой информации.",
                EnumSet.of(VulnerabilityType.SQL_INJECTION, VulnerabilityType.NOSQL_INJECTION,
                    VulnerabilityType.COMMAND_INJECTION, VulnerabilityType.LDAP_INJECTION,
                    VulnerabilityType.EXCESSIVE_DATA_EXPOSURE, VulnerabilityType.SENSITIVE_DATA_IN_URL),
                1.0));
        }

        if (types.contains(VulnerabilityType.UNSAFE_API_CONSUMPTION)
            && containsAny(types, VulnerabilityType.SQL_INJECTION, VulnerabilityType.SSRF,
            VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW)) {
            Severity severity = adjustSeverity(Severity.HIGH, context);
            risks.add(new CorrelatedRisk(
                "SUPPLY_CHAIN",
                "Supply Chain Abuse (" + endpointLabel + ")",
                severity,
                List.of("Unsafe API Consumption", "External attack surface"),
                List.of("Уязвимый партнёр", "Инъекция данных", "Компрометация цепочки поставок"),
                "Потребление небезопасных внешних API вместе с обнаруженными инъекционными техниками " +
                    "или SSRF открывает путь для атак через сторонних поставщиков.",
                EnumSet.of(VulnerabilityType.UNSAFE_API_CONSUMPTION, VulnerabilityType.SQL_INJECTION,
                    VulnerabilityType.SSRF, VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW),
                0.7));
        }

        return risks;
    }

    private static boolean containsAny(Set<VulnerabilityType> types, VulnerabilityType... candidates) {
        for (VulnerabilityType candidate : candidates) {
            if (types.contains(candidate)) {
                return true;
            }
        }
        return false;
    }

    private record CorrelatedRisk(
        String key,
        String label,
        Severity severity,
        List<String> signals,
        List<String> steps,
        String description,
        Set<VulnerabilityType> types,
        double scoreBoost
    ) { }

    private static String buildPathDescription(AttackChainSummary chain) {
        StringBuilder sb = new StringBuilder();
        sb.append("Severity: ").append(Optional.ofNullable(chain.getSeverity()).orElse("UNKNOWN"));
        if (chain.getDataSensitivityLevel() != null) {
            sb.append(", Data Sensitivity: ").append(chain.getDataSensitivityLevel());
        }
        if (chain.isExploitable()) {
            sb.append(", exploitable");
        }
        if (chain.getSteps() != null && !chain.getSteps().isEmpty()) {
            sb.append(". Steps: ").append(String.join(" → ", chain.getSteps()));
        }
        return sb.toString();
    }

    private static void addDataProtectionNodes(DataProtectionSummary summary,
                                               Map<String, String> endpointNodes,
                                               Map<String, String> vulnerabilityIdToNode,
                                               Map<String, ThreatNode> nodeMap,
                                               List<ThreatEdge> edges,
                                               List<ThreatPath> paths,
                                               Map<String, String> entryPointMap) {
        if (summary == null || summary.getExposures() == null || summary.getExposures().isEmpty()) {
            return;
        }

        for (PiiExposure exposure : summary.getExposures()) {
            if (exposure == null) {
                continue;
            }
            String method = normalize(exposure.getMethod());
            String endpoint = normalize(exposure.getEndpoint());
            String endpointKey = normalizeKey(method + " " + endpoint);
            String endpointNodeId = endpointNodes.get(endpointKey);
            if (endpointNodeId == null) {
                ThreatNode endpointNode = ThreatNode.builder()
                    .id("ENDPOINT:" + endpointKey)
                    .type("ENDPOINT")
                    .label(method + " " + endpoint)
                    .severity(exposure.getSeverity())
                    .score(severityScore(exposure.getSeverity()))
                    .build();
                nodeMap.put(endpointNode.getId(), endpointNode);
                endpointNodeId = endpointNode.getId();
                endpointNodes.put(endpointKey, endpointNodeId);
            }

            String exposureNodeId = "PII:" + endpointKey;
            if (nodeMap.containsKey(exposureNodeId)) {
                continue;
            }

            LinkedHashMap<String, String> metadata = new LinkedHashMap<>();
            metadata.put("unauthorized", String.valueOf(exposure.isUnauthorizedAccess()));
            metadata.put("consentMissing", String.valueOf(exposure.isConsentMissing()));
            metadata.put("insecureTransport", String.valueOf(exposure.isInsecureTransport()));

            List<String> signals = new ArrayList<>();
            if (exposure.getSignals() != null) {
                signals.addAll(exposure.getSignals());
            }
            if (Boolean.TRUE.equals(exposure.isUnauthorizedAccess())) {
                signals.add("Unauthorized Flow");
            }
            if (Boolean.TRUE.equals(exposure.isConsentMissing())) {
                signals.add("Consent Missing");
            }
            if (Boolean.TRUE.equals(exposure.isInsecureTransport())) {
                signals.add("Insecure Transport");
            }

            Severity nodeSeverity = exposure.getSeverity() != null ? exposure.getSeverity() : Severity.MEDIUM;
            if (Boolean.TRUE.equals(exposure.isUnauthorizedAccess())) {
                nodeSeverity = elevate(nodeSeverity);
            }
            if (Boolean.TRUE.equals(exposure.isConsentMissing())) {
                nodeSeverity = elevate(nodeSeverity);
            }
            if (Boolean.TRUE.equals(exposure.isInsecureTransport())) {
                nodeSeverity = elevate(nodeSeverity);
            }
            double nodeScore = severityScore(nodeSeverity)
                + (Boolean.TRUE.equals(exposure.isUnauthorizedAccess()) ? 1.0 : 0)
                + (Boolean.TRUE.equals(exposure.isConsentMissing()) ? 0.5 : 0)
                + (Boolean.TRUE.equals(exposure.isInsecureTransport()) ? 0.5 : 0);

            ThreatNode exposureNode = ThreatNode.builder()
                .id(exposureNodeId)
                .type("DATA_EXPOSURE")
                .label("PII Exposure " + method + " " + endpoint)
                .severity(nodeSeverity)
                .score(nodeScore)
                .signals(signals)
                .metadata(metadata)
                .build();
            nodeMap.put(exposureNodeId, exposureNode);

            edges.add(ThreatEdge.builder()
                .from(endpointNodeId)
                .to(exposureNodeId)
                .type("DATA_FLOW")
                .label("PII")
                .build());

            if (exposure.getVulnerabilityIds() != null) {
                for (String vulnId : exposure.getVulnerabilityIds()) {
                    String nodeId = vulnerabilityIdToNode.get(normalize(vulnId));
                    if (nodeId != null && nodeMap.containsKey(nodeId)) {
                        edges.add(ThreatEdge.builder()
                            .from(exposureNodeId)
                            .to(nodeId)
                            .type("EVIDENCE")
                            .label("evidence")
                            .build());
                    }
                }
            }

            ThreatPath path = ThreatPath.builder()
                .name("PII Exposure → " + method + " " + endpoint)
                .severity(nodeSeverity)
                .score(exposureNode.getScore())
                .nodeIds(buildPathNodeIds(entryPointMap, endpointNodeId, exposureNodeId))
                .steps(buildExposureSteps(exposure))
                .description(buildExposureDescription(exposure))
                .build();
            paths.add(path);
        }

        if (summary.getRecommendedActions() != null && !summary.getRecommendedActions().isEmpty()) {
            String recommendationNodeId = "DATA:RECOMMENDATIONS";
            ThreatNode recommendationNode = nodeMap.computeIfAbsent(recommendationNodeId, id -> ThreatNode.builder()
                .id(id)
                .type("RECOMMENDATION")
                .label("Data Protection Recommendations")
                .severity(Severity.MEDIUM)
                .score(1.5)
                .signals(new ArrayList<>(summary.getRecommendedActions()))
                .build());
            recommendationNode.getSignals().clear();
            recommendationNode.getSignals().addAll(summary.getRecommendedActions());

            for (String exposureNodeId : nodeMap.keySet()) {
                if (exposureNodeId.startsWith("PII:")) {
                    edges.add(ThreatEdge.builder()
                        .from(exposureNodeId)
                        .to(recommendationNodeId)
                        .type("REMEDIATION")
                        .label("recommendations")
                        .build());
                }
            }
        }
    }

    private static List<String> buildExposureSteps(PiiExposure exposure) {
        List<String> steps = new ArrayList<>();
        steps.add("Detect exposure");
        if (Boolean.TRUE.equals(exposure.isUnauthorizedAccess())) {
            steps.add("Unauthorized access to PII");
        }
        if (Boolean.TRUE.equals(exposure.isConsentMissing())) {
            steps.add("Missing consent controls");
        }
        if (Boolean.TRUE.equals(exposure.isInsecureTransport())) {
            steps.add("Insecure transport");
        }
        if (exposure.getSignals() != null && !exposure.getSignals().isEmpty()) {
            steps.add("Signals: " + String.join(", ", exposure.getSignals()));
        }
        return steps;
    }

    private static String buildExposureDescription(PiiExposure exposure) {
        StringBuilder description = new StringBuilder("PII exposure detected");
        if (Boolean.TRUE.equals(exposure.isUnauthorizedAccess())) {
            description.append(" — endpoint допускает неавторизованный доступ к данным");
        }
        if (Boolean.TRUE.equals(exposure.isConsentMissing())) {
            description.append(" — отсутствует подтверждённый consent workflow");
        }
        if (Boolean.TRUE.equals(exposure.isInsecureTransport())) {
            description.append(" — данные передаются без защищённого транспорта");
        }
        if (exposure.getSignals() != null && !exposure.getSignals().isEmpty()) {
            description.append(". Signals: ").append(String.join(", ", exposure.getSignals()));
        }
        return description.toString();
    }

    private static String normalize(String value) {
        if (value == null) {
            return "";
        }
        return value.trim();
    }
}

