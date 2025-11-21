package com.vtb.scanner.analysis;

import com.vtb.scanner.analysis.SchemaConstraintAnalyzer.SchemaConstraints;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Utility that inspects OpenAPI schemas/parameters and emits PII signals based on names, formats and patterns.
 */
public final class SchemaPiiInspector {

    private static final Set<String> HIGH_RISK_KEYWORDS = Set.of(
        "password", "secret", "private", "apikey", "api_key", "clientsecret", "client-secret",
        "token", "refresh", "jwt", "cvc", "cvv", "iban", "bic", "card", "pan", "pin",
        "passport", "ssn", "snils", "driverslicense", "driver_license", "passportseries",
        "licensekey", "licencekey"
    );

    private static final Set<String> PII_KEYWORDS = Set.of(
        "user", "username", "userid", "customer", "client", "account", "accnumber",
        "phone", "mobile", "msisdn", "email", "mail", "address", "geo", "location",
        "birth", "dob", "gender", "fullname", "fio", "inn", "snils", "tax", "passport",
        "document", "vin", "vehicle", "device", "imei", "imsi", "iccid", "session",
        "cookie", "profile", "personal", "pii", "pd", "pdn"
    );

    private static final Set<String> HIGH_RISK_FORMATS = Set.of("password", "byte", "binary");
    private static final Set<String> PII_FORMATS = Set.of(
        "email", "uuid", "date", "date-time", "uri", "hostname", "ipv4", "ipv6", "phone", "tel"
    );

    private static final Pattern NUMERIC_PATTERN = Pattern.compile("(?:^|[^\\d])(\\d{10,})(?:[^\\d]|$)");

    private SchemaPiiInspector() {
    }

    public static PiiSignal inspectParameter(Parameter parameter, SchemaConstraintAnalyzer analyzer) {
        if (parameter == null || analyzer == null || parameter.getName() == null) {
            return null;
        }
        SchemaConstraints constraints = analyzer.analyzeParameter(parameter);
        String pointer = "param." + Optional.ofNullable(parameter.getIn()).orElse("unknown") + "." + parameter.getName();
        return inspect(parameter.getName(), parameter.getDescription(), pointer, constraints);
    }

    public static List<PiiSignal> collectFromSchema(Schema<?> schema,
                                                    SchemaConstraintAnalyzer analyzer,
                                                    String pointerPrefix) {
        List<PiiSignal> signals = new ArrayList<>();
        collect(schema, analyzer, pointerPrefix != null ? pointerPrefix : "schema", null, new LinkedHashSet<>(), signals);
        return signals;
    }

    private static void collect(Schema<?> schema,
                                SchemaConstraintAnalyzer analyzer,
                                String pointer,
                                String fieldName,
                                Set<Schema<?>> visited,
                                List<PiiSignal> signals) {
        if (schema == null || analyzer == null || !visited.add(schema)) {
            return;
        }
        SchemaConstraints constraints = analyzer.analyzeSchema(schema);
        if (fieldName != null) {
            PiiSignal signal = inspect(fieldName, schema.getDescription(), pointer, constraints);
            if (signal != null) {
                signals.add(signal);
            }
        }
        if (schema.getProperties() != null) {
            schema.getProperties().forEach((name, value) -> {
                if (value instanceof Schema<?> child) {
                    String childPointer = pointer + "." + name;
                    collect(child, analyzer, childPointer, name, new LinkedHashSet<>(visited), signals);
                }
            });
        }
        if (schema.getAllOf() != null) {
            schema.getAllOf().forEach(sub ->
                collect(sub, analyzer, pointer, fieldName, new LinkedHashSet<>(visited), signals));
        }
        if (schema.getOneOf() != null) {
            int index = 0;
            for (Schema<?> sub : schema.getOneOf()) {
                collect(sub, analyzer, pointer + ".oneOf[" + index + "]", fieldName, new LinkedHashSet<>(visited), signals);
                index++;
            }
        }
        if (schema.getAnyOf() != null) {
            int index = 0;
            for (Schema<?> sub : schema.getAnyOf()) {
                collect(sub, analyzer, pointer + ".anyOf[" + index + "]", fieldName, new LinkedHashSet<>(visited), signals);
                index++;
            }
        }
        if (schema.getItems() != null) {
            collect(schema.getItems(), analyzer, pointer + "[]", fieldName, new LinkedHashSet<>(visited), signals);
        }
        if (schema.getAdditionalProperties() instanceof Schema<?>) {
            collect((Schema<?>) schema.getAdditionalProperties(), analyzer, pointer + ".{}", fieldName, new LinkedHashSet<>(visited), signals);
        }
    }

    public static PiiSignal inspect(String fieldName,
                                    String description,
                                    String pointer,
                                    SchemaConstraints constraints) {
        if (fieldName == null) {
            return null;
        }
        String normalized = (fieldName + " " + Optional.ofNullable(description).orElse("")).toLowerCase(Locale.ROOT);
        List<String> reasons = new ArrayList<>();
        boolean highRisk = false;

        String keyword = findKeyword(normalized, HIGH_RISK_KEYWORDS);
        if (keyword != null) {
            reasons.add("keyword=" + keyword);
            highRisk = true;
        } else {
            String piiKeyword = findKeyword(normalized, PII_KEYWORDS);
            if (piiKeyword != null) {
                reasons.add("keyword=" + piiKeyword);
            }
        }

        String format = constraints != null ? constraints.getFormat() : null;
        if (format != null) {
            if (HIGH_RISK_FORMATS.contains(format)) {
                reasons.add("format=" + format);
                highRisk = true;
            } else if (PII_FORMATS.contains(format)) {
                reasons.add("format=" + format);
            }
        }

        if (constraints != null && constraints.getPattern() != null &&
            NUMERIC_PATTERN.matcher(constraints.getPattern()).find()) {
            reasons.add("pattern=" + constraints.getPattern());
        }

        if (reasons.isEmpty()) {
            return null;
        }

        return new PiiSignal(pointer != null ? pointer : fieldName, fieldName, constraints, highRisk, String.join(", ", reasons));
    }

    private static String findKeyword(String text, Set<String> keywords) {
        for (String keyword : keywords) {
            if (keyword != null && !keyword.isBlank() && text.contains(keyword)) {
                return keyword;
            }
        }
        return null;
    }

    public record PiiSignal(String pointer,
                            String fieldName,
                            SchemaConstraints constraints,
                            boolean highRisk,
                            String reason) {
        public String evidence() {
            StringBuilder sb = new StringBuilder();
            sb.append(pointer != null ? pointer : fieldName);
            if (reason != null && !reason.isBlank()) {
                sb.append(" → ").append(reason);
            }
            if (constraints != null) {
                String guard = constraints.buildEvidenceNote();
                if (guard != null && !guard.isBlank()) {
                    sb.append(" (").append(guard).append(")");
                }
            }
            return sb.toString();
        }
    }
}

