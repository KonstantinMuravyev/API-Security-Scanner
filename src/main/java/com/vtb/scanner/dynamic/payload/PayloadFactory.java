package com.vtb.scanner.dynamic.payload;

import com.vtb.scanner.models.AttackChainSummary;
import com.vtb.scanner.models.AttackSurfaceSummary;
import com.vtb.scanner.models.EntryPointSummary;
import lombok.extern.slf4j.Slf4j;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
public class PayloadFactory {

    public List<PayloadBlueprint> build(AttackSurfaceSummary summary) {
        List<PayloadBlueprint> blueprints = new ArrayList<>();
        if (summary == null) {
            return blueprints;
        }
        if (summary.getEntryPointDetails() != null) {
            for (EntryPointSummary entry : summary.getEntryPointDetails()) {
                PayloadBlueprint sensitive = buildSensitivePayload(entry);
                if (sensitive != null) {
                    blueprints.add(sensitive);
                }
                PayloadBlueprint ssrf = buildSsrfPayload(entry);
                if (ssrf != null) {
                    blueprints.add(ssrf);
                }
                PayloadBlueprint injection = buildInjectionPayload(entry);
                if (injection != null) {
                    blueprints.add(injection);
                }
                PayloadBlueprint privilege = buildPrivilegePayload(entry);
                if (privilege != null) {
                    blueprints.add(privilege);
                }
            }
        }
        if (summary.getAttackChains() != null) {
            for (AttackChainSummary chain : summary.getAttackChains()) {
                PayloadBlueprint bola = buildBolaPayload(chain);
                if (bola != null) {
                    blueprints.add(bola);
                }
            }
        }
        return blueprints;
    }

    private PayloadBlueprint buildSensitivePayload(EntryPointSummary entry) {
        if (entry == null || entry.getSensitiveFields() == null || entry.getSensitiveFields().isEmpty()) {
            return null;
        }
        String path = normalizePath(entry.getPath());
        if (path == null) {
            return null;
        }
        String method = entry.getMethod() != null ? entry.getMethod().toUpperCase(Locale.ROOT) : "GET";
        String body = buildJsonPayload(entry.getSensitiveFields());
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        String description = "PII probe for sensitive fields (" + entry.getSensitiveFields().size() + ")";

        return PayloadBlueprint.builder()
            .id("pii-" + safeId(entry.getKey(), path))
            .type(PayloadType.SENSITIVE_DATA)
            .method(method)
            .path(path)
            .body(body)
            .headers(headers)
            .expectedStatus(entry.isRequiresAuth() ? 401 : null)
            .enforceAuth(entry.isRequiresAuth() && !entry.isStrongAuth())
            .description(description)
            .build();
    }

    private PayloadBlueprint buildSsrfPayload(EntryPointSummary entry) {
        if (entry == null || entry.getSsrfParameters() == null || entry.getSsrfParameters().isEmpty()) {
            return null;
        }
        String path = normalizePath(entry.getPath());
        if (path == null) {
            return null;
        }
        String param = entry.getSsrfParameters().get(0);
        if (param == null || param.isBlank()) {
            return null;
        }
        String attackUrl = "http://169.254.169.254/latest/meta-data/hostname";
        String craftedPath = appendQueryParam(path, param,
            URLEncoder.encode(attackUrl, StandardCharsets.UTF_8));

        return PayloadBlueprint.builder()
            .id("ssrf-" + safeId(entry.getKey(), path + "-" + param))
            .type(PayloadType.SSRF_PROBE)
            .method(entry.getMethod() != null ? entry.getMethod() : "GET")
            .path(craftedPath)
            .headers(Map.of("X-Dynamic-Test", "SSRF-Probe"))
            .expectedStatus(entry.isRequiresAuth() ? 401 : null)
            .enforceAuth(entry.isRequiresAuth() && !entry.isStrongAuth())
            .description("SSRF probe for parameter " + param)
            .build();
    }

    private PayloadBlueprint buildInjectionPayload(EntryPointSummary entry) {
        if (entry == null || entry.getInjectionParameters() == null || entry.getInjectionParameters().isEmpty()) {
            return null;
        }
        String path = normalizePath(entry.getPath());
        if (path == null) {
            return null;
        }
        String param = entry.getInjectionParameters().get(0);
        if (param == null || param.isBlank()) {
            return null;
        }
        String payload = URLEncoder.encode("' OR 1=1 --", StandardCharsets.UTF_8);
        String craftedPath = appendQueryParam(path, param, payload);

        return PayloadBlueprint.builder()
            .id("injection-" + safeId(entry.getKey(), path + "-" + param))
            .type(PayloadType.INJECTION_PROBE)
            .method(entry.getMethod() != null ? entry.getMethod() : "GET")
            .path(craftedPath)
            .headers(Map.of("X-Dynamic-Test", "Injection-Probe"))
            .enforceAuth(entry.isRequiresAuth() && !entry.isStrongAuth())
            .description("Generic SQL/Command payload for " + param)
            .build();
    }

    private PayloadBlueprint buildPrivilegePayload(EntryPointSummary entry) {
        if (entry == null || entry.getPrivilegeParameters() == null || entry.getPrivilegeParameters().isEmpty()) {
            return null;
        }
        String path = normalizePath(entry.getPath());
        if (path == null) {
            return null;
        }
        String param = entry.getPrivilegeParameters().get(0);
        if (param == null || param.isBlank()) {
            return null;
        }
        String method = entry.getMethod() != null ? entry.getMethod().toUpperCase(Locale.ROOT) : "GET";
        String description = "Privilege escalation probe for parameter " + param;
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-Dynamic-Test", "BFLA-Probe");
        String body = null;
        String craftedPath = path;
        if ("GET".equals(method)) {
            craftedPath = appendQueryParam(path, param, URLEncoder.encode("admin", StandardCharsets.UTF_8));
        } else {
            headers.put("Content-Type", "application/json");
            body = buildSingleFieldJson(param, "admin");
        }
        return PayloadBlueprint.builder()
            .id("bfla-" + safeId(entry.getKey(), path + "-" + param))
            .type(PayloadType.BFLA_PROBE)
            .method(method)
            .path(craftedPath)
            .headers(headers)
            .body(body)
            .enforceAuth(true)
            .description(description)
            .build();
    }

    private PayloadBlueprint buildBolaPayload(AttackChainSummary chain) {
        if (chain == null || chain.getTarget() == null) {
            return null;
        }
        String type = chain.getType() != null ? chain.getType().toUpperCase(Locale.ROOT) : "";
        if (!"BOLA".equals(type)) {
            return null;
        }
        MethodPathSignature signature = parseSignature(chain.getTarget());
        if (signature == null || signature.path() == null) {
            return null;
        }
        String path = normalizePath(signature.path());
        if (path == null) {
            return null;
        }
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-Dynamic-Test", "BOLA-Probe");
        String description = "BOLA replay using synthetic victim identifier";

        return PayloadBlueprint.builder()
            .id("bola-" + safeId(chain.getTarget(), path))
            .type(PayloadType.BOLA_PROBE)
            .method(signature.method())
            .path(pathWithMarker(path))
            .headers(headers)
            .expectedStatus(401)
            .enforceAuth(true)
            .description(description)
            .build();
    }

    private String pathWithMarker(String path) {
        if (path == null) {
            return null;
        }
        if (path.contains("?")) {
            return path + "&victimId=dynamic-test";
        }
        return path + "?victimId=dynamic-test";
    }

    private String buildJsonPayload(List<String> sensitiveFields) {
        if (sensitiveFields == null || sensitiveFields.isEmpty()) {
            return "{\"dynamic\":\"probe\"}";
        }
        Map<String, String> payload = new LinkedHashMap<>();
        List<String> uniqueFields = sensitiveFields.stream()
            .filter(f -> f != null && !f.isBlank())
            .map(this::extractFieldName)
            .filter(name -> !name.isBlank())
            .distinct()
            .limit(6)
            .collect(Collectors.toList());
        if (uniqueFields.isEmpty()) {
            uniqueFields.add("identifier");
        }
        int counter = 0;
        for (String field : uniqueFields) {
            payload.put(field, "DYNA-" + field.toUpperCase(Locale.ROOT) + "-" + (++counter));
        }
        return toJson(payload);
    }

    private String toJson(Map<String, String> payload) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : payload.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(escape(entry.getKey())).append('"')
                .append(':')
                .append('"').append(escape(entry.getValue())).append('"');
        }
        sb.append('}');
        return sb.toString();
    }

    private String buildSingleFieldJson(String field, String value) {
        Map<String, String> payload = new LinkedHashMap<>();
        payload.put(extractFieldName(field), value);
        return toJson(payload);
    }

    private String appendQueryParam(String path, String param, String value) {
        if (path == null || param == null || param.isBlank()) {
            return path;
        }
        StringBuilder builder = new StringBuilder(path);
        if (path.contains("?")) {
            builder.append('&');
        } else {
            builder.append('?');
        }
        builder.append(param).append('=').append(value != null ? value : "");
        return builder.toString();
    }

    private String escape(String value) {
        return value == null ? "" : value.replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r");
    }

    private String extractFieldName(String descriptor) {
        if (descriptor == null) {
            return "";
        }
        String normalized = descriptor.trim();
        if (normalized.contains(".")) {
            normalized = normalized.substring(normalized.lastIndexOf('.') + 1);
        }
        if (normalized.contains("/")) {
            normalized = normalized.substring(normalized.lastIndexOf('/') + 1);
        }
        normalized = normalized.replaceAll("[^a-zA-Z0-9_]", "");
        if (normalized.isBlank()) {
            return "field";
        }
        return normalized;
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
        return new MethodPathSignature(method.isEmpty() ? "GET" : method.toUpperCase(Locale.ROOT), path);
    }

    private String safeId(String candidate, String fallback) {
        String value = candidate != null ? candidate : fallback;
        if (value == null) {
            return "payload";
        }
        String normalized = value.replaceAll("[^a-zA-Z0-9_-]", "_");
        if (normalized.length() > 60) {
            normalized = normalized.substring(0, 60);
        }
        return normalized;
    }

    private record MethodPathSignature(String method, String path) {}
}

