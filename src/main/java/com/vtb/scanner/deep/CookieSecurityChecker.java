package com.vtb.scanner.deep;

import com.vtb.scanner.heuristics.ConfidenceCalculator;
import com.vtb.scanner.heuristics.SmartAnalyzer;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.semantic.ContextAnalyzer;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.examples.Example;
import io.swagger.v3.oas.models.headers.Header;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class CookieSecurityChecker {
    
    private static final Pattern COOKIE_NAME_PATTERN = Pattern.compile("^\\s*([^=;]+?)\\s*=");
    private static final Pattern ATTRIBUTE_PATTERN = Pattern.compile("(?i)(httponly|secure|samesite\\s*=\\s*[^;]+|domain\\s*=\\s*[^;]+|path\\s*=\\s*[^;]+|max-age\\s*=\\s*[^;]+|expires\\s*=\\s*[^;]+)");
    private static final Set<String> SENSITIVE_COOKIE_NAMES = Set.of(
        "session", "sessionid", "jsessionid", "phpsessid",
        "auth", "token", "access_token", "refresh_token",
        "jwt", "id_token", "oauth", "rememberme", "csrftoken"
    );

    private CookieSecurityChecker() {
    }

    public static List<Vulnerability> checkCookies(
        OpenAPI openAPI,
        ContextAnalyzer.APIContext context
    ) {
        log.info("Анализ cookie security (context={})", context);
        List<Vulnerability> findings = new ArrayList<>();
        if (openAPI == null || openAPI.getPaths() == null) {
            return findings;
        }

        Set<String> emitted = new HashSet<>();

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
                if (operation == null || operation.getResponses() == null || operation.getResponses().isEmpty()) {
                    continue;
                }

                operation.getResponses().forEach((status, rawResponse) -> {
                    ApiResponse response = resolveApiResponse(rawResponse, openAPI);
                    if (response == null || response.getHeaders() == null || response.getHeaders().isEmpty()) {
                        return;
                    }
                    response.getHeaders().forEach((headerName, header) -> {
                        if (!"set-cookie".equalsIgnoreCase(headerName)) {
                            return;
                        }
                        Set<String> samples = extractHeaderSamples(header);
                        if (samples.isEmpty()) {
                            samples.add(Optional.ofNullable(header.getDescription()).orElse(""));
                        }
                        for (String sample : samples) {
                            CookieAttributes attributes = parseCookieAttributes(sample);
                            if (attributes == null) {
                                continue;
                            }
                            List<CookieFinding> issues = analyzeAttributes(attributes, context);
                            if (issues.isEmpty()) {
                                continue;
                            }
                            int riskScore = SmartAnalyzer.calculateRiskScore(path, method, operation, openAPI);
                            Severity baseSeverity = SmartAnalyzer.severityFromRiskScore(riskScore);
                            for (CookieFinding issue : issues) {
                                Severity severity = escalateSeverity(issue.severity, baseSeverity);
                                emitFinding(findings, emitted, path, method, attributes.cookieName, issue, severity, operation, riskScore, context);
                            }
                        }
                    });
                });
            }
        }

        analyzeSecuritySchemes(openAPI, context, findings, emitted);

        log.info("Cookie Security: {} issues", findings.size());
        return findings;
    }

    private static void analyzeSecuritySchemes(OpenAPI openAPI,
                                               ContextAnalyzer.APIContext context,
                                               List<Vulnerability> findings,
                                               Set<String> emitted) {
        if (openAPI.getComponents() == null || openAPI.getComponents().getSecuritySchemes() == null) {
            return;
        }
        openAPI.getComponents().getSecuritySchemes().forEach((name, scheme) -> {
            if (scheme == null ||
                scheme.getType() == null ||
                scheme.getIn() == null ||
                scheme.getType() != SecurityScheme.Type.APIKEY ||
                scheme.getIn() != SecurityScheme.In.COOKIE) {
                return;
            }
            String description = Optional.ofNullable(scheme.getDescription()).orElse("");
            CookieAttributes attributes = parseCookieAttributes(description);
            if (attributes == null) {
                attributes = new CookieAttributes();
                attributes.cookieName = name;
                attributes.raw = description;
                attributes.descriptionOnly = true;
                attributes.detectSensitive();
                attributes.detectJwt();
                attributes.httpOnly = description.toLowerCase(Locale.ROOT).contains("httponly");
                attributes.secure = description.toLowerCase(Locale.ROOT).contains("secure");
                if (description.toLowerCase(Locale.ROOT).contains("samesite")) {
                    String lower = description.toLowerCase(Locale.ROOT);
                    int idx = lower.indexOf("samesite");
                    if (idx >= 0) {
                        attributes.sameSite = "specified";
                    }
                }
            }
            List<CookieFinding> issues = analyzeAttributes(attributes, context);
            if (issues.isEmpty()) {
                return;
            }
            for (CookieFinding issue : issues) {
                Severity severity = escalateSeverity(issue.severity, Severity.HIGH);
                emitComponentFinding(findings, emitted, name, issue, severity);
            }
        });
    }

    private static void emitFinding(List<Vulnerability> findings,
                                    Set<String> emitted,
                                    String path,
                                    String method,
                                    String cookieName,
                                    CookieFinding issue,
                                    Severity severity,
                                    Operation operation,
                                    int riskScore,
                                    ContextAnalyzer.APIContext context) {
        String key = String.join("|",
            path,
            method,
            cookieName != null ? cookieName : "unknown",
            issue.type);
        if (!emitted.add(key)) {
            return;
        }
        Vulnerability temp = Vulnerability.builder()
            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
            .severity(severity)
            .riskScore(riskScore)
            .build();

        findings.add(Vulnerability.builder()
            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                VulnerabilityType.SECURITY_MISCONFIGURATION,
                path,
                method,
                cookieName,
                issue.type))
            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
            .severity(severity)
            .riskScore(riskScore)
            .title(issue.title)
            .description(issue.description)
            .endpoint(path + " [cookie:" + (cookieName != null ? cookieName : issue.type) + "]")
            .method(method + "|COOKIE")
            .recommendation(issue.recommendation)
            .owaspCategory("API8:2023 - Security Misconfiguration (Cookie Hardening)")
            .evidence(issue.evidence)
            .confidence(ConfidenceCalculator.calculateConfidence(temp, operation, false, true))
            .priority(ConfidenceCalculator.calculatePriority(temp,
                ConfidenceCalculator.calculateConfidence(temp, operation, false, true)))
            .build());
    }

    private static void emitComponentFinding(List<Vulnerability> findings,
                                             Set<String> emitted,
                                             String cookieName,
                                             CookieFinding issue,
                                             Severity severity) {
        String key = "components|" + (cookieName != null ? cookieName : "unknown") + "|" + issue.type;
        if (!emitted.add(key)) {
            return;
        }
        Vulnerability temp = Vulnerability.builder()
            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
            .severity(severity)
            .build();

        findings.add(Vulnerability.builder()
            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                VulnerabilityType.SECURITY_MISCONFIGURATION,
                "components/securitySchemes",
                "N/A",
                cookieName,
                issue.type))
            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
            .severity(severity)
            .title(issue.title)
            .description(issue.description)
            .endpoint("components/securitySchemes")
            .method("CONFIG|COOKIE")
            .recommendation(issue.recommendation)
            .owaspCategory("API8:2023 - Security Misconfiguration (Cookie Hardening)")
            .evidence(issue.evidence)
            .confidence(ConfidenceCalculator.calculateConfidence(temp, null, false, true))
            .priority(ConfidenceCalculator.calculatePriority(temp,
                ConfidenceCalculator.calculateConfidence(temp, null, false, true)))
            .build());
    }

    private static Severity escalateSeverity(Severity issueSeverity, Severity baseSeverity) {
        if (issueSeverity.compareTo(baseSeverity) > 0) {
            return issueSeverity;
        }
        return baseSeverity.compareTo(issueSeverity) > 0 ? baseSeverity : issueSeverity;
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

    private static Set<String> extractHeaderSamples(Header header) {
        Set<String> samples = new LinkedHashSet<>();
        if (header == null) {
            return samples;
        }
        if (header.getExample() != null) {
            samples.add(header.getExample().toString());
        }
        if (header.getExamples() != null) {
            header.getExamples().values().stream()
                .filter(Objects::nonNull)
                .map(Example::getValue)
                .filter(Objects::nonNull)
                .forEach(value -> samples.add(value.toString()));
        }
        Schema<?> schema = header.getSchema();
        if (schema != null) {
            if (schema.getExample() != null) {
                samples.add(schema.getExample().toString());
            }
            if (schema.getDefault() != null) {
                samples.add(schema.getDefault().toString());
            }
            if (schema.getEnum() != null) {
                schema.getEnum().stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .forEach(samples::add);
            }
        }
        if (header.getDescription() != null) {
            samples.add(header.getDescription());
        }
        return samples;
    }

    private static CookieAttributes parseCookieAttributes(String rawSample) {
        if (rawSample == null) {
            return null;
        }
        String sample = rawSample.trim();
        if (sample.isEmpty()) {
            return null;
        }
        if (sample.toLowerCase(Locale.ROOT).startsWith("set-cookie:")) {
            sample = sample.substring("set-cookie:".length()).trim();
        }
        if (!sample.contains("=")) {
            return null;
        }
        CookieAttributes attributes = new CookieAttributes();
        attributes.raw = sample;

        Matcher matcher = COOKIE_NAME_PATTERN.matcher(sample);
        if (matcher.find()) {
            attributes.cookieName = matcher.group(1).trim();
        }
        String[] parts = sample.split(";");
        if (parts.length > 0) {
            String valuePart = parts[0];
            int eq = valuePart.indexOf('=');
            if (eq >= 0 && eq + 1 < valuePart.length()) {
                attributes.value = valuePart.substring(eq + 1).trim();
                attributes.detectJwt();
                attributes.detectSensitive();
            }
        }
        for (int i = 1; i < parts.length; i++) {
            String attribute = parts[i].trim();
            if (attribute.isEmpty()) {
                continue;
            }
            String lower = attribute.toLowerCase(Locale.ROOT);
            if ("httponly".equals(lower)) {
                attributes.httpOnly = true;
            } else if ("secure".equals(lower)) {
                attributes.secure = true;
            } else if (lower.startsWith("samesite")) {
                int idx = lower.indexOf('=');
                attributes.sameSite = idx >= 0 ? lower.substring(idx + 1).trim() : "unspecified";
            } else if (lower.startsWith("domain=")) {
                attributes.domain = attribute.substring(attribute.indexOf('=') + 1).trim();
            } else if (lower.startsWith("path=")) {
                attributes.path = attribute.substring(attribute.indexOf('=') + 1).trim();
        }
        }
        if (attributes.cookieName == null || attributes.cookieName.isBlank()) {
            attributes.cookieName = guessCookieName(sample);
        }
        return attributes;
    }

    private static String guessCookieName(String sample) {
        Matcher matcher = ATTRIBUTE_PATTERN.matcher(sample);
        int end = matcher.find() ? matcher.start() : sample.length();
        String base = sample.substring(0, end);
        int eq = base.indexOf('=');
        if (eq > 0) {
            return base.substring(0, eq).trim();
        }
        return "cookie";
    }

    private static List<CookieFinding> analyzeAttributes(CookieAttributes attributes,
                                                         ContextAnalyzer.APIContext context) {
        List<CookieFinding> findings = new ArrayList<>();
        boolean highContext = context == ContextAnalyzer.APIContext.BANKING ||
            context == ContextAnalyzer.APIContext.GOVERNMENT ||
            context == ContextAnalyzer.APIContext.HEALTHCARE;
        boolean sensitive = attributes.sensitive || attributes.jwt;

        if (!attributes.httpOnly) {
            Severity severity = sensitive || highContext ? Severity.CRITICAL : Severity.HIGH;
            findings.add(new CookieFinding(
                "MissingHttpOnly",
                "Cookie без HttpOnly",
                "Cookie '" + attributes.cookieName + "' не содержит HttpOnly. " +
                    "XSS-атака позволит украсть сессионные или токен-переменные.",
                "Добавьте HttpOnly, чтобы сделать cookie недоступной JavaScript-коду. " +
                    "Для API с JWT/сессиями это критично.",
                "Sample: " + attributes.raw,
                severity
            ));
        }

        if (!attributes.secure) {
            Severity severity = sensitive || highContext ? Severity.CRITICAL : Severity.HIGH;
            findings.add(new CookieFinding(
                "MissingSecure",
                "Cookie без Secure",
                "Cookie '" + attributes.cookieName + "' не содержит Secure. " +
                    "Её можно перехватить через незашифрованный канал (HTTP).",
                "Добавьте Secure, чтобы отправка происходила только по HTTPS. " +
                    "Для банков/финансов это обязательное требование.",
                "Sample: " + attributes.raw,
                severity
            ));
        }

        if (attributes.sameSite == null) {
            Severity severity = sensitive || highContext ? Severity.HIGH : Severity.MEDIUM;
            findings.add(new CookieFinding(
                "MissingSameSite",
                "Cookie без SameSite",
                "Cookie '" + attributes.cookieName + "' не задаёт SameSite. " +
                    "Это повышает риск CSRF-атак.",
                "Укажите SameSite=Strict (для критичных сессий) или SameSite=Lax. " +
                    "Для сценариев с межсайтовым доступом используйте SameSite=None; Secure.",
                "Sample: " + attributes.raw,
                severity
            ));
        } else if ("none".equalsIgnoreCase(attributes.sameSite) && !attributes.secure) {
            Severity severity = sensitive || highContext ? Severity.CRITICAL : Severity.HIGH;
            findings.add(new CookieFinding(
                "SameSiteNoneWithoutSecure",
                "SameSite=None требует Secure",
                "Cookie '" + attributes.cookieName + "' объявлена с SameSite=None, но без Secure. " +
                    "Это нарушает требования браузеров и открывает CSRF/злоупотребления каналами.",
                "Всегда сочетайте SameSite=None с Secure и HTTPS. Проверьте, что это намеренное решение.",
                "Sample: " + attributes.raw,
                severity
            ));
        }

        if (sensitive && (attributes.path == null || attributes.path.isBlank())) {
            findings.add(new CookieFinding(
                "NoPathForSensitive",
                "Отсутствует Path для чувствительной cookie",
                "Cookie '" + attributes.cookieName + "' содержит токен/чувствительные данные, но Path не ограничен. " +
                    "Cookie отправляется на все эндпоинты домена.",
                "Установите Path с минимально необходимой областью (например, /api/auth).",
                "Sample: " + attributes.raw,
                highContext ? Severity.MEDIUM : Severity.LOW
            ));
        }

        if (sensitive && attributes.domain != null && attributes.domain.startsWith(".")) {
            findings.add(new CookieFinding(
                "WildcardDomain",
                "Cookie с wildcard domain",
                "Cookie '" + attributes.cookieName + "' используется для чувствительных данных, но Domain начинается с '.' " +
                    "и позволяет отправку на поддомены.",
                "Существенно ограничьте Domain (конкретный сервис) или вообще не задавайте его, чтобы cookie была host-only.",
                "Domain=" + attributes.domain,
                highContext ? Severity.HIGH : Severity.MEDIUM
            ));
        }

        if (attributes.jwt && !attributes.httpOnly) {
            findings.add(new CookieFinding(
                "JwtWithoutHttpOnly",
                "JWT хранится в cookie без HttpOnly",
                "Cookie '" + attributes.cookieName + "' содержит JWT (обнаружен формат header.payload.signature), " +
                    "но HttpOnly не установлен. Это позволяет XSS-атаке украсть токен.",
                "Храните JWT только в HttpOnly cookie или в secure storage, который недоступен для произвольного JavaScript.",
                "Sample: " + attributes.raw,
                sensitive || highContext ? Severity.CRITICAL : Severity.HIGH
            ));
        }

        if (attributes.descriptionOnly && !attributes.httpOnly && !attributes.secure && !attributes.sameSiteSpecified()) {
            findings.add(new CookieFinding(
                "CookiePolicyMissingDetails",
                "Cookie policy не описывает атрибуты безопасности",
                "Описание cookie '" + attributes.cookieName + "' не содержит требований HttpOnly/Secure/SameSite.",
                "Дополните документацию и реализацию. Без атрибутов cookie уязвима к XSS/CSRF/перехвату.",
                "Description: " + attributes.raw,
                highContext ? Severity.HIGH : Severity.MEDIUM
            ));
        }

        return findings;
    }

    private static class CookieAttributes {
        String raw;
        String cookieName;
        String value;
        boolean httpOnly;
        boolean secure;
        String sameSite;
        String domain;
        String path;
        boolean jwt;
        boolean sensitive;
        boolean descriptionOnly;

        void detectJwt() {
            if (value == null) {
                return;
            }
            if (value.chars().filter(ch -> ch == '.').count() == 2) {
                this.jwt = true;
            }
        }

        void detectSensitive() {
            if (cookieName != null) {
                String lower = cookieName.toLowerCase(Locale.ROOT);
                for (String token : SENSITIVE_COOKIE_NAMES) {
                    if (lower.contains(token)) {
                        this.sensitive = true;
                        break;
                    }
                }
            }
            if (value != null && value.length() > 20) {
                this.sensitive = true;
            }
        }

        boolean sameSiteSpecified() {
            return sameSite != null;
        }
    }

    private static class CookieFinding {
        final String type;
        final String title;
        final String description;
        final String recommendation;
        final String evidence;
        final Severity severity;

        CookieFinding(String type,
                      String title,
                      String description,
                      String recommendation,
                      String evidence,
                                                           Severity severity) {
            this.type = type;
            this.title = title;
            this.description = description;
            this.recommendation = recommendation;
            this.evidence = evidence;
            this.severity = severity;
        }
    }
}
