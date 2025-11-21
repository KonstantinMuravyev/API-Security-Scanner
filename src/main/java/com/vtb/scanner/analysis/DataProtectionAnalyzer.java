package com.vtb.scanner.analysis;

import com.vtb.scanner.models.AttackSurfaceSummary;
import com.vtb.scanner.models.DataProtectionSummary;
import com.vtb.scanner.models.PiiExposure;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.semantic.ContextAnalyzer;
import com.vtb.scanner.util.AccessControlHeuristics;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class DataProtectionAnalyzer {

    private static final Set<VulnerabilityType> EXPOSURE_TYPES = Set.of(
        VulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
        VulnerabilityType.SENSITIVE_DATA_IN_URL,
        VulnerabilityType.SECURITY_MISCONFIGURATION,
        VulnerabilityType.SECRET_LEAK
    );

    private static final Set<VulnerabilityType> UNAUTHORIZED_TYPES = Set.of(
        VulnerabilityType.BOLA,
        VulnerabilityType.BFLA,
        VulnerabilityType.BROKEN_AUTHENTICATION,
        VulnerabilityType.BROKEN_OBJECT_PROPERTY
    );

    private static final Set<String> PII_KEYWORDS = Set.of(
        "passport", "паспорт", "snils", "снилс", "inn", "инн", "tax id",
        "bank account", "iban", "card number", "credit card", "cvc", "cvv",
        "phone", "телефон", "email", "e-mail", "mail",
        "address", "адрес",
        "personal data", "персональные данные",
        "pii", "pdn", "персональные",
        "consent", "permissions", "allowed accounts", "psu", "tpp",
        "msisdn", "subscriber", "vin", "vehicle", "telematics",
        "customer", "client", "user id", "session id", "token"
    );

    private static final Set<String> STORAGE_KEYWORDS = Set.of(
        "export", "download", "report", "backup", "dump", "archive", "csv", "excel",
        " выгруз", "экспорт", "отчёт", "архив"
    );

    private static final Set<String> LOGGING_KEYWORDS = Set.of(
        "log", "logging", "diagnostic", "trace", "stacktrace", "debug",
        " access log", " audit", "журнал", "лог"
    );

    private static final Set<String> INSECURE_TRANSPORT_KEYS = Set.of(
        "MISC-HTTP", "HTTP", "TLS", "ssl", "transport"
    );

    private static final Set<String> CONSENT_KEYWORDS = Set.of(
        "consent", "permissions", "x-consent-id", "allowed_creditor_accounts",
        "allowed product types", "qualified signature", "esid", "esia", "gosuslugi", "sbbol"
    );

    private DataProtectionAnalyzer() {}

    public static DataProtectionSummary analyze(List<Vulnerability> vulnerabilities,
                                                AttackSurfaceSummary attackSurface,
                                                ContextAnalyzer.APIContext context,
                                                OpenAPI openAPI) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return DataProtectionSummary.builder().build();
        }

        Map<String, ExposureAccumulator> exposureBuilders = new HashMap<>();
        int totalSignals = 0;
        int criticalExposures = 0;
        int unauthorizedFlows = 0;
        boolean consentMissingDetected = false;
        boolean storageExposureDetected = false;
        boolean loggingExposureDetected = false;
        Set<String> highRiskChains = new LinkedHashSet<>();
        Set<String> recommendedActions = new LinkedHashSet<>();

        for (Vulnerability vulnerability : vulnerabilities) {
            if (vulnerability == null) {
                continue;
            }
            String method = normalizeMethod(vulnerability.getMethod());
            OperationContext operationContext = resolveOperation(openAPI, vulnerability.getEndpoint(), method);
            String endpoint = operationContext != null ? operationContext.path() : normalize(vulnerability.getEndpoint());
            String key = endpoint + "|" + method;
            ExposureAccumulator builder = exposureBuilders.computeIfAbsent(
                key,
                k -> new ExposureAccumulator(endpoint, method)
            );

            String combinedText = toLower(
                vulnerability.getTitle(),
                vulnerability.getDescription(),
                vulnerability.getEvidence()
            );

            Operation resolvedOperation = operationContext != null ? operationContext.operation() : null;
            String pathForAccess = operationContext != null ? operationContext.path() : null;
            boolean hasExplicitAccess = resolvedOperation != null && pathForAccess != null &&
                AccessControlHeuristics.hasExplicitAccessControl(resolvedOperation, pathForAccess, openAPI);
            boolean hasConsentEvidence = resolvedOperation != null && AccessControlHeuristics.hasConsentEvidence(resolvedOperation, openAPI);
            boolean hasStrongAuthorization = resolvedOperation != null && AccessControlHeuristics.hasStrongAuthorization(resolvedOperation, openAPI);

            boolean isExposureType = EXPOSURE_TYPES.contains(vulnerability.getType())
                || containsAny(combinedText, PII_KEYWORDS);
            boolean isUnauthorizedType = UNAUTHORIZED_TYPES.contains(vulnerability.getType());
            boolean mentionsConsent = containsAny(combinedText, CONSENT_KEYWORDS) || hasConsentEvidence;
            boolean isInsecureTransport = containsAny(normalize(vulnerability.getId()), INSECURE_TRANSPORT_KEYS)
                || containsAny(combinedText, INSECURE_TRANSPORT_KEYS);
            boolean storageSignal = containsAny(endpoint.toLowerCase(Locale.ROOT), STORAGE_KEYWORDS)
                || containsAny(combinedText, STORAGE_KEYWORDS);
            boolean loggingSignal = containsAny(combinedText, LOGGING_KEYWORDS);

            if (isExposureType) {
                builder.signals.add(resolveSignalLabel(vulnerability));
                builder.vulnerabilityIds.add(normalize(vulnerability.getId()));
                builder.severity = resolveSeverity(builder.severity, vulnerability.getSeverity());
                totalSignals++;
                if (vulnerability.getSeverity() != null && vulnerability.getSeverity().compareTo(Severity.HIGH) >= 0) {
                    criticalExposures++;
                }
                recommendedActions.add("Включить data masking для " + endpoint);
                if (vulnerability.getType() == VulnerabilityType.SECRET_LEAK) {
                    recommendedActions.add("Удалить секреты из спецификации и выполнить ротацию ключей/токенов");
                }
            }

            if (isUnauthorizedType) {
                builder.unauthorizedAccess = true;
                builder.signals.add(vulnerability.getType().name());
                builder.vulnerabilityIds.add(normalize(vulnerability.getId()));
                unauthorizedFlows++;
                recommendedActions.add("Усилить авторизацию и consent проверки на " + endpoint);
            }

            boolean consentRequired = shouldRequireConsent(context, vulnerability.getType(), combinedText);
            boolean consentMissing = consentRequired && !mentionsConsent && !hasExplicitAccess && !hasStrongAuthorization;
            if (consentMissing) {
                builder.consentMissing = true;
                consentMissingDetected = true;
                recommendedActions.add("Задокументировать и применять consent workflow для " + endpoint);
            }

            if (isInsecureTransport) {
                builder.insecureTransport = true;
                recommendedActions.add("Перевести транспорт для " + endpoint + " на TLS 1.2+");
            }

            if (storageSignal) {
                builder.signals.add("Storage Export");
                storageExposureDetected = true;
                recommendedActions.add("Добавить шифрование и контроль доступа для выгрузок на " + endpoint);
            }

            if (loggingSignal) {
                builder.signals.add("Logging/Trace Signal");
                loggingExposureDetected = true;
                recommendedActions.add("Проверить логи на отсутствие персональных данных; настроить masking");
            }

            if (isExposureType && isUnauthorizedType) {
                highRiskChains.add("Комбинация утечки данных и эскалации привилегий: " + method + " " + endpoint);
            }
        }

        if (attackSurface != null && attackSurface.getEntryPointCount() > 10) {
            recommendedActions.add("Ограничить доступ к чувствительным entry points (" + attackSurface.getEntryPointCount() + ")");
        }
        if (context == ContextAnalyzer.APIContext.BANKING || context == ContextAnalyzer.APIContext.GOVERNMENT) {
            recommendedActions.add("Провести PSD2/152-ФЗ аудит согласий и хранения данных");
        }

        recommendedActions.removeIf(Objects::isNull);

        List<PiiExposure> exposures = new ArrayList<>();
        for (ExposureAccumulator accumulator : exposureBuilders.values()) {
            if (accumulator.signals.isEmpty()) {
                continue;
            }
            PiiExposure exposure = PiiExposure.builder()
                .endpoint(accumulator.endpoint)
                .method(accumulator.method)
                .severity(accumulator.severity)
                .signals(accumulator.signals)
                .vulnerabilityIds(accumulator.vulnerabilityIds)
                .unauthorizedAccess(accumulator.unauthorizedAccess)
                .consentMissing(accumulator.consentMissing)
                .insecureTransport(accumulator.insecureTransport)
                .build();
            if (!exposure.getSignals().isEmpty()) {
                exposures.add(exposure);
            }
        }
        exposures.sort((a, b) -> b.getSeverity().compareTo(a.getSeverity()));

        int finalConsentGaps = (int) exposures.stream().filter(PiiExposure::isConsentMissing).count();
        boolean finalInsecureTransport = exposures.stream().anyMatch(PiiExposure::isInsecureTransport);
        if (finalConsentGaps > 0) {
            consentMissingDetected = true;
        }

        return DataProtectionSummary.builder()
            .totalSignals(totalSignals)
            .criticalExposures(criticalExposures)
            .unauthorizedFlows(unauthorizedFlows)
            .consentGapCount(finalConsentGaps)
            .insecureTransportDetected(finalInsecureTransport)
            .consentMissingDetected(consentMissingDetected)
            .storageExposureDetected(storageExposureDetected)
            .loggingExposureDetected(loggingExposureDetected)
            .exposures(exposures)
            .highRiskChains(new ArrayList<>(highRiskChains))
            .recommendedActions(recommendedActions)
            .build();
    }

    private static Severity resolveSeverity(Severity current, Severity candidate) {
        if (candidate == null) {
            return current;
        }
        if (current == null) {
            return candidate;
        }
        return candidate.compareTo(current) > 0 ? candidate : current;
    }

    private static String resolveSignalLabel(Vulnerability vulnerability) {
        if (vulnerability.getTitle() != null && !vulnerability.getTitle().isBlank()) {
            return vulnerability.getTitle();
        }
        if (vulnerability.getType() != null) {
            return vulnerability.getType().name();
        }
        return "PII Signal";
    }

    private static boolean containsAny(String text, Set<String> tokens) {
        if (text == null || text.isEmpty()) {
            return false;
        }
        for (String token : tokens) {
            if (token == null || token.isEmpty()) {
                continue;
            }
            if (text.contains(token.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static String toLower(String... values) {
        StringBuilder sb = new StringBuilder();
        if (values != null) {
            for (String value : values) {
                if (value != null) {
                    sb.append(value.toLowerCase(Locale.ROOT)).append(' ');
                }
            }
        }
        return sb.toString();
    }

    private static String normalize(String text) {
        if (text == null) {
            return "N/A";
        }
        String trimmed = text.trim();
        return trimmed.isEmpty() ? "N/A" : trimmed;
    }

    private static String normalizeMethod(String method) {
        if (method == null || method.isBlank()) {
            return "N/A";
        }
        return method.toUpperCase(Locale.ROOT);
    }

    private static boolean shouldRequireConsent(ContextAnalyzer.APIContext context,
                                                VulnerabilityType type,
                                                String combinedText) {
        if (containsAny(combinedText, CONSENT_KEYWORDS)) {
            return true;
        }
        if (context == ContextAnalyzer.APIContext.BANKING || context == ContextAnalyzer.APIContext.GOVERNMENT) {
            return true;
        }
        return type == VulnerabilityType.BOLA || type == VulnerabilityType.BFLA;
    }

    private static OperationContext resolveOperation(OpenAPI openAPI, String rawEndpoint, String rawMethod) {
        if (openAPI == null || openAPI.getPaths() == null || openAPI.getPaths().isEmpty()) {
            return null;
        }
        String normalizedMethod = rawMethod != null && !rawMethod.isBlank()
            ? rawMethod.toUpperCase(Locale.ROOT)
            : null;
        String candidatePath = normalizeEndpointPath(rawEndpoint);
        if (candidatePath == null) {
            return null;
        }
        PathItem direct = openAPI.getPaths().get(candidatePath);
        Operation op = extractOperation(direct, normalizedMethod);
        if (op != null) {
            return new OperationContext(candidatePath, op);
        }
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String template = entry.getKey();
            if (pathMatchesTemplate(candidatePath, template)) {
                Operation templateOp = extractOperation(entry.getValue(), normalizedMethod);
                if (templateOp != null) {
                    return new OperationContext(template, templateOp);
                }
            }
        }
        return null;
    }

    private static Operation extractOperation(PathItem pathItem, String method) {
        if (pathItem == null) {
            return null;
        }
        if (method == null || method.isBlank()) {
            if (pathItem.getGet() != null) return pathItem.getGet();
            if (pathItem.getPost() != null) return pathItem.getPost();
            if (pathItem.getPut() != null) return pathItem.getPut();
            if (pathItem.getDelete() != null) return pathItem.getDelete();
            if (pathItem.getPatch() != null) return pathItem.getPatch();
            if (pathItem.getHead() != null) return pathItem.getHead();
            if (pathItem.getOptions() != null) return pathItem.getOptions();
            return null;
        }
        return switch (method) {
            case "GET" -> pathItem.getGet();
            case "POST" -> pathItem.getPost();
            case "PUT" -> pathItem.getPut();
            case "DELETE" -> pathItem.getDelete();
            case "PATCH" -> pathItem.getPatch();
            case "HEAD" -> pathItem.getHead();
            case "OPTIONS" -> pathItem.getOptions();
            case "TRACE" -> pathItem.getTrace();
            default -> null;
        };
    }

    private static String normalizeEndpointPath(String rawEndpoint) {
        if (rawEndpoint == null || rawEndpoint.isBlank()) {
            return null;
        }
        String candidate = rawEndpoint.trim();
        if (candidate.startsWith("http://") || candidate.startsWith("https://")) {
            try {
                java.net.URI uri = new java.net.URI(candidate);
                candidate = uri.getPath();
            } catch (Exception ignored) {
                // fallback to original
            }
        }
        if (candidate == null || candidate.isBlank()) {
            return null;
        }
        if (!candidate.startsWith("/")) {
            candidate = "/" + candidate;
        }
        if (candidate.length() > 1 && candidate.endsWith("/")) {
            candidate = candidate.substring(0, candidate.length() - 1);
        }
        return candidate;
    }

    private static boolean pathMatchesTemplate(String candidatePath, String template) {
        if (candidatePath == null || template == null) {
            return false;
        }
        if (template.equals(candidatePath)) {
            return true;
        }
        String regex = buildTemplateRegex(template);
        return candidatePath.matches(regex);
    }

    private static String buildTemplateRegex(String template) {
        StringBuilder regex = new StringBuilder("^");
        int length = template.length();
        for (int i = 0; i < length; i++) {
            char c = template.charAt(i);
            if (c == '{') {
                while (i < length && template.charAt(i) != '}') {
                    i++;
                }
                regex.append("[^/]+");
            } else {
                if (".^$|?*+()[{\\".indexOf(c) >= 0) {
                    regex.append('\\');
                }
                regex.append(c);
            }
        }
        regex.append("$");
        return regex.toString();
    }

    private static final class ExposureAccumulator {
        final String endpoint;
        final String method;
        Severity severity = Severity.MEDIUM;
        final LinkedHashSet<String> signals = new LinkedHashSet<>();
        final List<String> vulnerabilityIds = new ArrayList<>();
        boolean unauthorizedAccess = false;
        boolean consentMissing = false;
        boolean insecureTransport = false;

        ExposureAccumulator(String endpoint, String method) {
            this.endpoint = endpoint;
            this.method = method;
        }
    }

    private record OperationContext(String path, Operation operation) { }
}

