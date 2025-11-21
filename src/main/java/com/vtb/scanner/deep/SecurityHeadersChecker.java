package com.vtb.scanner.deep;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.heuristics.SmartAnalyzer;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.examples.Example;
import io.swagger.v3.oas.models.headers.Header;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Проверка Security Headers с контекстом и качественной аналитикой.
 */
@Slf4j
public class SecurityHeadersChecker {

    private static final Pattern MAX_AGE_PATTERN = Pattern.compile("max-age\\s*=\\s*(\\d+)", Pattern.CASE_INSENSITIVE);

    private SecurityHeadersChecker() {
    }

    public static List<Vulnerability> checkSecurityHeaders(
        OpenAPI openAPI,
        OpenAPIParser parser,
        com.vtb.scanner.semantic.ContextAnalyzer.APIContext context
    ) {
        log.info("Проверка Security Headers с учетом контекста {}...", context);
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (openAPI == null || openAPI.getPaths() == null || openAPI.getPaths().isEmpty()) {
            return vulnerabilities;
        }

        Map<String, List<HeaderIssue>> missingIssues = new LinkedHashMap<>();
        Map<String, List<HeaderIssue>> weakIssues = new LinkedHashMap<>();
        boolean anyHeadersFound = false;
        Map<String, Header> globalHeaders = collectGlobalHeaders(openAPI);

        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            if (pathItem == null) {
                continue;
            }

            Map<String, Operation> operations = collectOperations(pathItem);
            for (Map.Entry<String, Operation> opEntry : operations.entrySet()) {
                String method = opEntry.getKey();
                Operation operation = opEntry.getValue();
                if (operation == null || operation.getResponses() == null) {
                    continue;
                }

                for (Map.Entry<String, ApiResponse> responseEntry : operation.getResponses().entrySet()) {
                    ApiResponse response = resolveApiResponse(responseEntry.getValue(), openAPI);
                    if (response == null) {
                        continue;
                    }
                    Map<String, Header> headers = mergeHeaders(globalHeaders, response.getHeaders());
                    if (headers != null && !headers.isEmpty()) {
                        anyHeadersFound = true;
                    }
                    boolean requiresAuth = parser != null && parser.requiresAuthentication(operation);
                    int riskScore = SmartAnalyzer.calculateRiskScore(path, method, operation, openAPI);
                    assessHeader("Strict-Transport-Security", headers, path, method, context, missingIssues, weakIssues, requiresAuth, riskScore);
                    assessHeader("X-Frame-Options", headers, path, method, context, missingIssues, weakIssues, requiresAuth, riskScore);
                    assessHeader("X-Content-Type-Options", headers, path, method, context, missingIssues, weakIssues, requiresAuth, riskScore);
                    assessHeader("Content-Security-Policy", headers, path, method, context, missingIssues, weakIssues, requiresAuth, riskScore);
                    assessHeader("Permissions-Policy", headers, path, method, context, missingIssues, weakIssues, requiresAuth, riskScore);
                    assessHeader("Referrer-Policy", headers, path, method, context, missingIssues, weakIssues, requiresAuth, riskScore);
                    assessHeader("Cross-Origin-Opener-Policy", headers, path, method, context, missingIssues, weakIssues, requiresAuth, riskScore);
                    assessHeader("Cross-Origin-Embedder-Policy", headers, path, method, context, missingIssues, weakIssues, requiresAuth, riskScore);
                    assessHeader("X-XSS-Protection", headers, path, method, context, missingIssues, weakIssues, requiresAuth, riskScore);
                }
            }
        }

        if (!anyHeadersFound) {
            vulnerabilities.add(buildNoHeadersVulnerability(context));
            // При полном отсутствии остальных сообщений достаточно
            return vulnerabilities;
        }

        missingIssues.forEach((header, issues) -> vulnerabilities.add(
            buildHeaderVulnerability(header, issues, context, true)
        ));
        weakIssues.forEach((header, issues) -> vulnerabilities.add(
            buildHeaderVulnerability(header, issues, context, false)
        ));

        log.info("Security Headers анализ завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }

    private static Map<String, Operation> collectOperations(PathItem pathItem) {
        Map<String, Operation> operations = new LinkedHashMap<>();
        if (pathItem.getGet() != null) operations.put("GET", pathItem.getGet());
        if (pathItem.getPost() != null) operations.put("POST", pathItem.getPost());
        if (pathItem.getPut() != null) operations.put("PUT", pathItem.getPut());
        if (pathItem.getDelete() != null) operations.put("DELETE", pathItem.getDelete());
        if (pathItem.getPatch() != null) operations.put("PATCH", pathItem.getPatch());
        if (pathItem.getOptions() != null) operations.put("OPTIONS", pathItem.getOptions());
        if (pathItem.getHead() != null) operations.put("HEAD", pathItem.getHead());
        if (pathItem.getTrace() != null) operations.put("TRACE", pathItem.getTrace());
        return operations;
    }

    private static Map<String, Header> collectGlobalHeaders(OpenAPI openAPI) {
        Map<String, Header> globalHeaders = new LinkedHashMap<>();
        if (openAPI == null || openAPI.getComponents() == null) {
            return globalHeaders;
        }
        if (openAPI.getComponents().getHeaders() != null) {
            globalHeaders.putAll(openAPI.getComponents().getHeaders());
        }
        if (openAPI.getComponents().getResponses() != null) {
            openAPI.getComponents().getResponses().values().stream()
                .filter(Objects::nonNull)
                .map(ApiResponse::getHeaders)
                .filter(Objects::nonNull)
                .forEach(map -> map.forEach(globalHeaders::putIfAbsent));
        }
        return globalHeaders;
    }

    private static Map<String, Header> mergeHeaders(Map<String, Header> global, Map<String, Header> local) {
        Map<String, Header> merged = new LinkedHashMap<>();
        if (global != null && !global.isEmpty()) {
            merged.putAll(global);
        }
        if (local != null && !local.isEmpty()) {
            merged.putAll(local);
        }
        return merged;
    }

    private static void assessHeader(
        String headerName,
        Map<String, Header> headers,
        String path,
        String method,
        com.vtb.scanner.semantic.ContextAnalyzer.APIContext context,
        Map<String, List<HeaderIssue>> missingIssues,
        Map<String, List<HeaderIssue>> weakIssues,
        boolean requiresAuth,
        int riskScore
    ) {
        Header header = headers != null ? getHeaderIgnoreCase(headers, headerName) : null;
        Optional<String> value = resolveHeaderValue(header);

        HeaderState state = evaluateHeader(headerName, value.orElse(null), context);
        if (state.state == HeaderState.State.MISSING) {
            missingIssues.computeIfAbsent(headerName, k -> new ArrayList<>())
                .add(new HeaderIssue(path, method, state.reason, requiresAuth, riskScore));
        } else if (state.state == HeaderState.State.WEAK) {
            weakIssues.computeIfAbsent(headerName, k -> new ArrayList<>())
                .add(new HeaderIssue(path, method, state.reason, requiresAuth, riskScore));
        }
    }

    private static HeaderState evaluateHeader(
        String headerName,
        String rawValue,
        com.vtb.scanner.semantic.ContextAnalyzer.APIContext context
    ) {
        if (rawValue == null || rawValue.isBlank()) {
            return HeaderState.missing("Header отсутствует в responses");
        }
        String value = rawValue.trim().toLowerCase(Locale.ROOT);
        switch (headerName) {
            case "Strict-Transport-Security":
                Matcher matcher = MAX_AGE_PATTERN.matcher(value);
                if (!matcher.find()) {
                    return HeaderState.weak("Не задан max-age. Рекомендуется ≥ 31536000");
                }
                long maxAge = Long.parseLong(matcher.group(1));
                if (maxAge < 31_536_000L) {
                    return HeaderState.weak("max-age слишком мал (" + maxAge + "), рекомендуется ≥ 31536000");
                }
                if (!value.contains("includesubdomains")) {
                    return HeaderState.weak("Нет includeSubDomains. Для банков/гос требуется полное покрытие");
                }
                if ((context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.BANKING ||
                    context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.GOVERNMENT ||
                    context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.HEALTHCARE ||
                    context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.TELECOM ||
                    context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.AUTOMOTIVE) &&
                    !value.contains("preload")) {
                    return HeaderState.weak("Для критичных доменов (bank/gov/healthcare/telecom/telematics) рекомендуется preload");
                }
                return HeaderState.ok();
            case "X-Frame-Options":
                if (!(value.contains("deny") || value.contains("sameorigin"))) {
                    return HeaderState.weak("Значение должно быть DENY или SAMEORIGIN");
                }
                return HeaderState.ok();
            case "X-Content-Type-Options":
                if (!"nosniff".equals(value)) {
                    return HeaderState.weak("Должно быть nosniff");
                }
                return HeaderState.ok();
            case "Content-Security-Policy":
                if (value.contains("default-src") && value.contains("'self'")) {
                    return HeaderState.ok();
                }
                if (value.contains("*")) {
                    return HeaderState.weak("Содержит wildcard (*), CSP ослаблена");
                }
                return HeaderState.weak("Не задан default-src 'self'");
            case "Permissions-Policy":
                if (value.contains("*")) {
                    return HeaderState.weak("Перечислите явно разрешенные стратегии, не используйте *");
                }
                return HeaderState.ok();
            case "Referrer-Policy":
                if (value.contains("no-referrer") || value.contains("same-origin") || value.contains("strict-origin")) {
                    return HeaderState.ok();
                }
                return HeaderState.weak("Рекомендуется no-referrer или strict-origin");
            case "Cross-Origin-Opener-Policy":
                if (!value.contains("same-origin")) {
                    return HeaderState.weak("COOP должен быть same-origin для защиты от XS-Leaks");
                }
                return HeaderState.ok();
            case "Cross-Origin-Embedder-Policy":
                if (!value.contains("require-corp")) {
                    return HeaderState.weak("COEP должен быть require-corp");
                }
                return HeaderState.ok();
            case "X-XSS-Protection":
                if (!value.startsWith("1")) {
                    return HeaderState.weak("Установите 1; mode=block или удалите header (современные браузеры игнорируют)");
                }
                return HeaderState.ok();
            default:
                return HeaderState.ok();
        }
    }

    private static Vulnerability buildNoHeadersVulnerability(
        com.vtb.scanner.semantic.ContextAnalyzer.APIContext context
    ) {
        boolean criticalContext = (context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.BANKING ||
            context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.GOVERNMENT ||
            context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.HEALTHCARE ||
            context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.TELECOM ||
            context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.AUTOMOTIVE);
        Severity severity = criticalContext ? Severity.CRITICAL : Severity.HIGH;
        int riskScore = criticalContext ? 190 : 140;

        Vulnerability temp = Vulnerability.builder()
            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
            .severity(severity)
            .riskScore(riskScore)
            .build();

        int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(temp, null, false, true);
        int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(temp, confidence);

        return Vulnerability.builder()
            .id("SEC-HEADERS-NONE")
            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
            .severity(severity)
            .riskScore(riskScore)
            .title("Отсутствуют Security Headers во всех ответах API")
            .description(
                "В спецификации нет ни одного ключевого security header. Это повышает риски:\n" +
                    "• Clickjacking (нет X-Frame-Options)\n" +
                    "• MITM downgrade (нет HSTS)\n" +
                    "• XSS (нет CSP)\n" +
                    "• MIME sniffing (нет X-Content-Type-Options)\n" +
                    "• Отсутствие modern web isolation (COOP/COEP)"
            )
            .endpoint("security-headers:global")
            .method("CONFIG")
            .recommendation(
                "Добавьте security headers в responses (200/4xx/5xx):\n" +
                    "Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,\n" +
                    "Permissions-Policy, Referrer-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy."
            )
            .owaspCategory("API8:2023 - Security Misconfiguration")
            .evidence("В спецификации отсутствуют security headers")
            .impactLevel(criticalContext ? "CRITICAL:No Browser Security Controls" : "HIGH:Missing Security Headers")
            .confidence(confidence)
            .priority(priority)
            .build();
    }

    private static Vulnerability buildHeaderVulnerability(
        String header,
        List<HeaderIssue> issues,
        com.vtb.scanner.semantic.ContextAnalyzer.APIContext context,
        boolean missing
    ) {
        Severity severity = determineSeverity(header, context, missing);
        if (issues.stream().anyMatch(issue -> issue.requiresAuth)) {
            severity = elevateSeverity(severity);
        }
        int maxRisk = issues.stream().mapToInt(issue -> issue.riskScore).max().orElse(0);

        String evidence = issues.stream()
            .limit(8)
            .map(issue -> issue.method + " " + issue.path +
                (issue.requiresAuth ? " [auth]" : "") +
                (issue.reason != null && !issue.reason.isBlank()
                ? " (" + issue.reason + ")"
                : ""))
            .reduce((a, b) -> a + "; " + b)
            .orElse("Нет примеров");

        Vulnerability temp = Vulnerability.builder()
            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
            .severity(severity)
            .riskScore(maxRisk)
            .build();

        int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(temp, null, false, true);
        int adjustedConfidence = Math.min(99, Math.max(confidence, 60 + (maxRisk / 2)));
        int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(temp, adjustedConfidence);

        return Vulnerability.builder()
            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                VulnerabilityType.SECURITY_MISCONFIGURATION,
                issues.get(0).path,
                issues.get(0).method,
                header,
                (missing ? "Missing" : "Weak") + " security header"
            ))
            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
            .severity(severity)
            .riskScore(maxRisk)
            .title((missing ? "Отсутствует" : "Ослаблен") + " header: " + header)
            .description(buildDescription(header, missing))
            .endpoint(issues.get(0).path + " [header:" + header + "]")
            .method(issues.get(0).method + "|HEADER")
            .recommendation(buildRecommendation(header))
            .owaspCategory("API8:2023 - Security Misconfiguration")
            .evidence(evidence)
            .impactLevel(determineImpact(header, missing, context))
            .confidence(adjustedConfidence)
            .priority(priority)
            .build();
    }

    private static Severity determineSeverity(
        String header,
        com.vtb.scanner.semantic.ContextAnalyzer.APIContext context,
        boolean missing
    ) {
        boolean highContext = (context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.BANKING ||
            context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.GOVERNMENT ||
            context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.HEALTHCARE ||
            context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.TELECOM ||
            context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.AUTOMOTIVE);

        if ("Strict-Transport-Security".equals(header) || "Content-Security-Policy".equals(header)) {
            return missing ? (highContext ? Severity.CRITICAL : Severity.HIGH) : Severity.HIGH;
        }
        if ("Permissions-Policy".equals(header) || "Cross-Origin-Opener-Policy".equals(header) ||
            "Cross-Origin-Embedder-Policy".equals(header)) {
            return missing ? Severity.MEDIUM : Severity.LOW;
        }
        if ("X-XSS-Protection".equals(header)) {
            return missing ? Severity.LOW : Severity.LOW;
        }
        return missing ? Severity.MEDIUM : Severity.MEDIUM;
    }

    private static Severity elevateSeverity(Severity base) {
        return switch (base) {
            case CRITICAL -> Severity.CRITICAL;
            case HIGH -> Severity.CRITICAL;
            case MEDIUM -> Severity.HIGH;
            case LOW -> Severity.MEDIUM;
            case INFO -> Severity.LOW;
        };
    }

    private static String buildDescription(String header, boolean missing) {
        if (missing) {
            switch (header) {
                case "Strict-Transport-Security":
                    return "HSTS отсутствует. Без него возможен downgrade атаки на HTTPS и MITM.";
                case "Content-Security-Policy":
                    return "CSP отсутствует. API не ограничивает источники контента, повышается риск XSS.";
                case "X-Frame-Options":
                    return "X-Frame-Options отсутствует. Возможны clickjacking атаки.";
                case "X-Content-Type-Options":
                    return "X-Content-Type-Options отсутствует. Возможен MIME sniffing у клиента.";
                case "Permissions-Policy":
                    return "Permissions-Policy отсутствует. Нельзя контролировать доступ к опасным API браузера.";
                case "Referrer-Policy":
                    return "Referrer-Policy отсутствует. Возможна утечка токенов/личных данных через Referer.";
                case "Cross-Origin-Opener-Policy":
                    return "COOP отсутствует. Возможны XS-Leaks и утечка данных между окнами.";
                case "Cross-Origin-Embedder-Policy":
                    return "COEP отсутствует. Нет защиты от небезопасных встраиваемых ресурсов.";
                case "X-XSS-Protection":
                    return "X-XSS-Protection отсутствует. Устаревшая защита, но стоит включить для совместимости.";
                default:
                    return "Security header отсутствует.";
            }
        } else {
            switch (header) {
                case "Strict-Transport-Security":
                    return "HSTS задан, но параметры ослаблены (малый max-age/нет includeSubDomains/preload).";
                case "Content-Security-Policy":
                    return "CSP задан, но содержит wildcard или не определяет default-src 'self'.";
                case "X-Frame-Options":
                    return "X-Frame-Options имеет нестандартное значение. Используйте DENY/SAMEORIGIN.";
                case "X-Content-Type-Options":
                    return "X-Content-Type-Options должен быть 'nosniff'.";
                case "Permissions-Policy":
                    return "Permissions-Policy содержит *, уточните списки разрешений.";
                case "Referrer-Policy":
                    return "Referrer-Policy не ограничивает передачу реферера. Используйте strict/no-referrer.";
                case "Cross-Origin-Opener-Policy":
                    return "COOP должен быть same-origin для защиты от XS-Leaks.";
                case "Cross-Origin-Embedder-Policy":
                    return "COEP должен быть require-corp.";
                case "X-XSS-Protection":
                    return "Установите 1; mode=block или удалите header (современный подход).";
                default:
                    return "Security header содержит слабое значение.";
            }
        }
    }

    private static String determineImpact(
        String header,
        boolean missing,
        com.vtb.scanner.semantic.ContextAnalyzer.APIContext context
    ) {
        boolean criticalContext = (context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.BANKING ||
            context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.GOVERNMENT ||
            context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.HEALTHCARE ||
            context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.TELECOM ||
            context == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.AUTOMOTIVE);

        switch (header) {
            case "Strict-Transport-Security":
                return missing
                    ? (criticalContext ? "CRITICAL:No Transport Encryption Hardening" : "HIGH:HSTS Missing")
                    : "HIGH:Weak HSTS Configuration";
            case "Content-Security-Policy":
                return missing
                    ? "CRITICAL:No CSP Against XSS"
                    : "HIGH:Weak CSP Allows Injection";
            case "X-Frame-Options":
                return missing
                    ? "HIGH:Clickjacking Exposure"
                    : "MEDIUM:Frame Policy Weak";
            case "X-Content-Type-Options":
                return missing
                    ? "MEDIUM:MIME Sniffing Risk"
                    : "LOW:Non-Nosniff Header";
            case "Permissions-Policy":
                return missing
                    ? (criticalContext ? "HIGH:Unrestricted Browser Capabilities" : "MEDIUM:Permissions Policy Missing")
                    : "MEDIUM:Overly Permissive Permissions";
            case "Referrer-Policy":
                return missing
                    ? "HIGH:Token Leak via Referer"
                    : "MEDIUM:Weak Referrer Policy";
            case "Cross-Origin-Opener-Policy":
                return missing
                    ? "HIGH:No COOP Isolation"
                    : "MEDIUM:Weak COOP";
            case "Cross-Origin-Embedder-Policy":
                return missing
                    ? (criticalContext ? "HIGH:No COEP Isolation" : "MEDIUM:COEP Missing")
                    : "MEDIUM:Weak COEP";
            case "X-XSS-Protection":
                return missing
                    ? "LOW:Legacy XSS Filter Disabled"
                    : "LOW:Weak Legacy XSS Filter";
            default:
                return missing ? "MEDIUM:Security Header Missing" : "MEDIUM:Security Header Weak";
        }
    }

    private static String buildRecommendation(String header) {
        switch (header) {
            case "Strict-Transport-Security":
                return "Пример: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload";
            case "Content-Security-Policy":
                return "Пример: Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'";
            case "X-Frame-Options":
                return "Пример: X-Frame-Options: DENY (или SAMEORIGIN для допустимого встраивания)";
            case "X-Content-Type-Options":
                return "Пример: X-Content-Type-Options: nosniff";
            case "Permissions-Policy":
                return "Пример: Permissions-Policy: camera=(), microphone=(), geolocation=(self)";
            case "Referrer-Policy":
                return "Пример: Referrer-Policy: no-referrer или strict-origin-when-cross-origin";
            case "Cross-Origin-Opener-Policy":
                return "Пример: Cross-Origin-Opener-Policy: same-origin";
            case "Cross-Origin-Embedder-Policy":
                return "Пример: Cross-Origin-Embedder-Policy: require-corp";
            case "X-XSS-Protection":
                return "Пример: X-XSS-Protection: 1; mode=block (для старых браузеров) или удалите header.";
            default:
                return "Укажите безопасное значение для " + header + ".";
        }
    }

    private static ApiResponse resolveApiResponse(ApiResponse response, OpenAPI openAPI) {
        if (response == null) {
            return null;
        }
        if (response.get$ref() == null || openAPI == null || openAPI.getComponents() == null ||
            openAPI.getComponents().getResponses() == null) {
            return response;
        }
        String ref = response.get$ref();
        String name = ref.substring(ref.lastIndexOf('/') + 1);
        ApiResponse resolved = openAPI.getComponents().getResponses().get(name);
        return resolved != null ? resolved : response;
    }

    private static Header getHeaderIgnoreCase(Map<String, Header> headers, String target) {
        if (headers == null) {
            return null;
        }
        for (Map.Entry<String, Header> entry : headers.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(target)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private static Optional<String> resolveHeaderValue(Header header) {
        if (header == null) {
            return Optional.empty();
        }
        if (header.getExample() != null) {
            return Optional.of(header.getExample().toString());
        }
        if (header.getExamples() != null) {
            for (Example example : header.getExamples().values()) {
                if (example != null && example.getValue() != null) {
                    return Optional.of(example.getValue().toString());
                }
            }
        }
        Schema<?> schema = header.getSchema();
        if (schema != null) {
            if (schema.getExample() != null) {
                return Optional.of(schema.getExample().toString());
            }
            if (schema.getDefault() != null) {
                return Optional.of(schema.getDefault().toString());
            }
            if (schema.getEnum() != null && !schema.getEnum().isEmpty()) {
                Object first = schema.getEnum().get(0);
                if (first != null) {
                    return Optional.of(first.toString());
                }
            }
        }
        return Optional.empty();
    }

    private static class HeaderIssue {
        final String path;
        final String method;
        final String reason;
        final boolean requiresAuth;
        final int riskScore;

        HeaderIssue(String path, String method, String reason, boolean requiresAuth, int riskScore) {
            this.path = path;
            this.method = method;
            this.reason = reason;
            this.requiresAuth = requiresAuth;
            this.riskScore = riskScore;
        }
    }

    private static class HeaderState {
        enum State { OK, MISSING, WEAK }

        final State state;
        final String reason;

        HeaderState(State state, String reason) {
            this.state = state;
            this.reason = reason;
        }

        static HeaderState ok() {
            return new HeaderState(State.OK, null);
        }

        static HeaderState missing(String reason) {
            return new HeaderState(State.MISSING, reason);
        }

        static HeaderState weak(String reason) {
            return new HeaderState(State.WEAK, reason);
        }
    }
}

