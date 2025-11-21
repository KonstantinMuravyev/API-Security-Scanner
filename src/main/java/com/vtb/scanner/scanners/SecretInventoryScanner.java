package com.vtb.scanner.scanners;

import com.vtb.scanner.analysis.SchemaConstraintAnalyzer;
import com.vtb.scanner.analysis.SchemaPiiInspector;
import com.vtb.scanner.analysis.SchemaPiiInspector.PiiSignal;
import com.vtb.scanner.config.ScannerConfig;
import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityIdGenerator;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.examples.Example;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Secret & Shadow Inventory Scanner (S14)
 * Detects exposed secrets, credentials and shadow/test environments inside the OpenAPI specification.
 */
@Slf4j
public class SecretInventoryScanner implements VulnerabilityScanner {

    private final List<Pattern> secretPatterns;
    private final List<String> secretIndicators;
    private final List<String> shadowKeywords;
    private SchemaConstraintAnalyzer constraintAnalyzer;

    public SecretInventoryScanner(String targetUrl) {
        ScannerConfig.SecretInventory inventory = ScannerConfig.load().getSecretInventory();

        this.secretPatterns = inventory != null && inventory.getSecretPatterns() != null
            ? compilePatterns(inventory.getSecretPatterns())
            : compilePatterns(defaultSecretPatterns());

        this.secretIndicators = inventory != null && inventory.getSecretIndicators() != null
            ? inventory.getSecretIndicators()
            : defaultSecretIndicators();

        this.shadowKeywords = inventory != null && inventory.getShadowEnvironmentKeywords() != null
            ? inventory.getShadowEnvironmentKeywords()
            : defaultShadowKeywords();
    }

    @Override
    public List<Vulnerability> scan(OpenAPI openAPI, OpenAPIParser parser) {
        log.info("Запуск SecretInventoryScanner...");
        if (openAPI == null) {
            return Collections.emptyList();
        }

        List<Vulnerability> vulnerabilities = new ArrayList<>();
        this.constraintAnalyzer = new SchemaConstraintAnalyzer(openAPI);
        try {
            detectShadowEnvironments(openAPI, vulnerabilities);
            detectSecrets(openAPI, vulnerabilities);
        } finally {
            this.constraintAnalyzer = null;
        }
        log.info("SecretInventoryScanner завершен. Найдено {} потенциальных проблем.", vulnerabilities.size());
        return vulnerabilities;
    }

    private void detectShadowEnvironments(OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        Set<String> urls = new LinkedHashSet<>();
        if (openAPI.getServers() != null) {
            openAPI.getServers().forEach(server -> {
                if (server != null && server.getUrl() != null) {
                    urls.add(server.getUrl());
                }
            });
        }

        if (openAPI.getPaths() != null) {
            for (PathItem pathItem : openAPI.getPaths().values()) {
                if (pathItem == null) {
                    continue;
                }
                if (pathItem.getServers() != null) {
                    pathItem.getServers().forEach(server -> {
                        if (server != null && server.getUrl() != null) {
                            urls.add(server.getUrl());
                        }
                    });
                }
                for (Operation operation : collectOperations(pathItem)) {
                    if (operation != null && operation.getServers() != null) {
                        operation.getServers().forEach(server -> {
                            if (server != null && server.getUrl() != null) {
                                urls.add(server.getUrl());
                            }
                        });
                    }
                }
            }
        }

        Set<String> reportedHosts = new HashSet<>();
        for (String url : urls) {
            if (url == null) {
                continue;
            }
            try {
                URI uri = URI.create(url);
                String host = Optional.ofNullable(uri.getHost()).orElse(url).toLowerCase(Locale.ROOT);
                if (isShadowHost(host) && reportedHosts.add(host)) {
                    Vulnerability vulnerability = Vulnerability.builder()
                        .id(VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SHADOW_API,
                            host,
                            "N/A",
                            null,
                            "Shadow environment host"))
                        .type(VulnerabilityType.SHADOW_API)
                        .severity(Severity.HIGH)
                        .title("Выявлен тестовый/теневой сервер в спецификации")
                        .description("Сервер \"" + host + "\" похож на dev/test/stage окружение. Убедитесь, что он не доступен из production." )
                        .endpoint(host)
                        .method("N/A")
                        .recommendation("Удалите тестовые URL из production спецификации или ограничьте к ним доступ (VPN/mTLS). Проведите ревизию shadow API.")
                        .owaspCategory("API9:2023 - Improper Inventory (Shadow API)")
                        .evidence("Server URL: " + url)
                        .confidence(85)
                        .priority(2)
                        .build();
                    vulnerabilities.add(vulnerability);
                }
            } catch (Exception e) {
                log.debug("Не удалось разобрать URL {}: {}", url, e.getMessage());
            }
        }
    }

    private boolean isShadowHost(String host) {
        if (host == null) {
            return false;
        }
        String lower = host.toLowerCase(Locale.ROOT);
        if (lower.contains("localhost") || lower.contains("127.0.0.1") || lower.contains("0.0.0.0")) {
            return true;
        }
        for (String keyword : shadowKeywords) {
            if (keyword != null && !keyword.isBlank() && lower.contains(keyword.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private void detectSecrets(OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        Set<String> secretReported = new HashSet<>();
        Set<String> piiReported = new HashSet<>();

        if (openAPI.getPaths() != null) {
            for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
                String path = entry.getKey();
                PathItem pathItem = entry.getValue();
                if (pathItem == null) {
                    continue;
                }
                scanOperation(path, "GET", pathItem.getGet(), vulnerabilities, secretReported, piiReported);
                scanOperation(path, "POST", pathItem.getPost(), vulnerabilities, secretReported, piiReported);
                scanOperation(path, "PUT", pathItem.getPut(), vulnerabilities, secretReported, piiReported);
                scanOperation(path, "DELETE", pathItem.getDelete(), vulnerabilities, secretReported, piiReported);
                scanOperation(path, "PATCH", pathItem.getPatch(), vulnerabilities, secretReported, piiReported);
                scanOperation(path, "OPTIONS", pathItem.getOptions(), vulnerabilities, secretReported, piiReported);
                scanOperation(path, "HEAD", pathItem.getHead(), vulnerabilities, secretReported, piiReported);
            }
        }

        if (openAPI.getComponents() != null) {
            if (openAPI.getComponents().getExamples() != null) {
                openAPI.getComponents().getExamples().forEach((name, example) -> {
                    if (example != null && example.getValue() != null) {
                        analyzeValue("components example " + name, "N/A", example.getValue(), vulnerabilities, secretReported);
                    }
                });
            }
            if (openAPI.getComponents().getSchemas() != null) {
                openAPI.getComponents().getSchemas().forEach((name, schema) -> {
                    analyzeSchemaLocation("schema " + name, "N/A", schema, "components." + name,
                        vulnerabilities, secretReported, piiReported);
                });
            }
            if (openAPI.getComponents().getSecuritySchemes() != null) {
                openAPI.getComponents().getSecuritySchemes().forEach((name, scheme) -> {
                    if (scheme == null) {
                        return;
                    }
                    if (scheme.getDescription() != null) {
                        analyzeValue("security scheme " + name, "N/A", scheme.getDescription(), vulnerabilities, secretReported);
                    }
                    if (scheme.getExtensions() != null) {
                        scheme.getExtensions().values().forEach(value -> analyzeValue("security scheme ext " + name, "N/A", value, vulnerabilities, secretReported));
                    }
                    if (scheme.getFlows() != null) {
                        if (scheme.getFlows().getClientCredentials() != null && scheme.getFlows().getClientCredentials().getTokenUrl() != null) {
                            analyzeValue("oauth clientCredentials " + name, "N/A", scheme.getFlows().getClientCredentials().getTokenUrl(), vulnerabilities, secretReported);
                        }
                    }
                });
            }
            if (openAPI.getComponents().getHeaders() != null) {
                openAPI.getComponents().getHeaders().forEach((name, header) -> {
                    if (header == null) {
                        return;
                    }
                    if (header.getDescription() != null) {
                        analyzeValue("header " + name, "N/A", header.getDescription(), vulnerabilities, secretReported);
                    }
                    if (header.getSchema() != null) {
                        analyzeSchemaLocation("header schema " + name, "N/A", header.getSchema(),
                            "header." + name, vulnerabilities, secretReported, piiReported);
                    }
                });
            }
        }
    }

    private void scanOperation(String path,
                               String method,
                               Operation operation,
                               List<Vulnerability> vulnerabilities,
                               Set<String> secretReported,
                               Set<String> piiReported) {
        if (operation == null) {
            return;
        }
        String location = method + " " + path;

        if (operation.getSummary() != null) {
            analyzeValue(location + " summary", method, operation.getSummary(), vulnerabilities, secretReported);
        }
        if (operation.getDescription() != null) {
            analyzeValue(location + " description", method, operation.getDescription(), vulnerabilities, secretReported);
        }

        if (operation.getParameters() != null) {
            for (Parameter parameter : operation.getParameters()) {
                if (parameter == null) {
                    continue;
                }
                String paramLocation = location + " parameter " + parameter.getName();
                if (parameter.getDescription() != null) {
                    analyzeValue(paramLocation, method, parameter.getDescription(), vulnerabilities, secretReported);
                }
                if (parameter.getExample() != null) {
                    analyzeValue(paramLocation, method, parameter.getExample(), vulnerabilities, secretReported);
                }
                if (parameter.getExamples() != null) {
                    parameter.getExamples().values().stream()
                        .filter(Objects::nonNull)
                        .map(Example::getValue)
                        .filter(Objects::nonNull)
                        .forEach(value -> analyzeValue(paramLocation, method, value, vulnerabilities, secretReported));
                }
                if (parameter.getSchema() != null) {
                    analyzeSchemaLocation(paramLocation, method, parameter.getSchema(),
                        "param." + Optional.ofNullable(parameter.getIn()).orElse("unknown") + "." + parameter.getName(),
                        vulnerabilities, secretReported, piiReported);
                }
                reportParameterPiiSignal(parameter, paramLocation, method, vulnerabilities, piiReported);
            }
        }

        if (operation.getRequestBody() != null && operation.getRequestBody().getContent() != null) {
            analyzeContent(location + " requestBody", method, operation.getRequestBody().getContent(), vulnerabilities,
                secretReported, piiReported);
        }

        if (operation.getResponses() != null) {
            operation.getResponses().forEach((status, response) -> {
                if (response == null) {
                    return;
                }
                if (response.getDescription() != null) {
                    analyzeValue(location + " response " + status, method, response.getDescription(), vulnerabilities, secretReported);
                }
                if (response.getContent() != null) {
                    analyzeContent(location + " response " + status, method, response.getContent(), vulnerabilities,
                        secretReported, piiReported);
                }
            });
        }
    }

    private void analyzeContent(String location,
                                String method,
                                Content content,
                                List<Vulnerability> vulnerabilities,
                                Set<String> secretReported,
                                Set<String> piiReported) {
        for (Map.Entry<String, MediaType> entry : content.entrySet()) {
            String media = entry.getKey();
            MediaType mediaType = entry.getValue();
            if (mediaType == null) {
                continue;
            }
            String context = location + " " + media;
            if (mediaType.getExample() != null) {
                analyzeValue(context, method, mediaType.getExample(), vulnerabilities, secretReported);
            }
            if (mediaType.getExamples() != null) {
                mediaType.getExamples().values().stream()
                    .filter(Objects::nonNull)
                    .map(Example::getValue)
                    .filter(Objects::nonNull)
                    .forEach(value -> analyzeValue(context, method, value, vulnerabilities, secretReported));
            }
            if (mediaType.getSchema() != null) {
                analyzeSchemaLocation(context, method, mediaType.getSchema(),
                    location + "." + media,
                    vulnerabilities, secretReported, piiReported);
            }
        }
    }

    private void analyzeSchemaLocation(String location,
                                       String method,
                                       Schema<?> schema,
                                       String pointer,
                                       List<Vulnerability> vulnerabilities,
                                       Set<String> secretReported,
                                       Set<String> piiReported) {
        if (schema == null) {
            return;
        }
        List<SchemaSample> samples = collectSchemaSamples(schema, pointer);
        analyzeSchemaSamples(location, method, samples, vulnerabilities, secretReported);
        reportSchemaPiiSignals(location, method, schema, pointer, vulnerabilities, piiReported);
    }

    private void analyzeSchemaSamples(String location,
                                      String method,
                                      List<SchemaSample> samples,
                                      List<Vulnerability> vulnerabilities,
                                      Set<String> secretReported) {
        if (samples == null) {
            return;
        }
        for (SchemaSample sample : samples) {
            if (sample == null || sample.value() == null) {
                continue;
            }
            handleSecretCandidate(location, method, sample.value(), sample.constraints(), sample.pointer(),
                vulnerabilities, secretReported);
        }
    }

    private void handleSecretCandidate(String location,
                                       String method,
                                       String candidate,
                                       SchemaConstraintAnalyzer.SchemaConstraints constraints,
                                       String pointer,
                                       List<Vulnerability> vulnerabilities,
                                       Set<String> secretReported) {
        SecretMatch match = detectSecret(candidate);
        if (match == null) {
            return;
        }
        reportSecretMatch(location, method, match, constraints, pointer, vulnerabilities, secretReported);
    }

    private void reportSecretMatch(String location,
                                   String method,
                                   SecretMatch match,
                                   SchemaConstraintAnalyzer.SchemaConstraints constraints,
                                   String pointer,
                                   List<Vulnerability> vulnerabilities,
                                   Set<String> reported) {
        String fingerprint = location + "|" + match.maskedPreview() + (pointer != null ? "|" + pointer : "");
        if (!reported.add(fingerprint)) {
            return;
        }
        Severity severity = adjustSeverityForGuard(match.severity(), constraints);
        int confidence = adjustConfidenceForGuard(match.confidence(), constraints);
        int priority = severity == Severity.CRITICAL ? 1 : Math.max(2, match.priority());
        String evidence = "Masked preview: " + match.maskedPreview();
        if (pointer != null) {
            evidence += " | field: " + pointer;
        }
        if (constraints != null) {
            String guard = constraints.buildEvidenceNote();
            if (guard != null) {
                evidence += " | " + guard;
            }
        }
        vulnerabilities.add(Vulnerability.builder()
            .id(VulnerabilityIdGenerator.generateId(
                VulnerabilityType.SECRET_LEAK,
                location,
                method != null ? method : "N/A",
                pointer,
                match.label()))
            .type(VulnerabilityType.SECRET_LEAK)
            .severity(severity)
            .title("Найден потенциальный секрет/credential в спецификации")
            .description("В " + location + " обнаружено значение, похожее на секрет или credential. Замените его плейсхолдером и выполните ротацию ключей.")
            .endpoint(location)
            .method(method != null ? method : "N/A")
            .recommendation("Удалите секрет из спецификации, используйте плейсхолдеры (***). Проведите ротацию ключей и настройте scanning в CI.")
            .owaspCategory("API9:2023 - Improper Inventory (Secret Leak)")
            .confidence(confidence)
            .priority(priority)
            .evidence(evidence)
            .build());
    }

    private void reportSchemaPiiSignals(String location,
                                        String method,
                                        Schema<?> schema,
                                        String pointer,
                                        List<Vulnerability> vulnerabilities,
                                        Set<String> piiReported) {
        if (schema == null || constraintAnalyzer == null) {
            return;
        }
        List<PiiSignal> signals = SchemaPiiInspector.collectFromSchema(schema, constraintAnalyzer, pointer);
        for (PiiSignal signal : signals) {
            reportPiiSignal(location, method, signal, vulnerabilities, piiReported);
        }
    }

    private void reportParameterPiiSignal(Parameter parameter,
                                          String location,
                                          String method,
                                          List<Vulnerability> vulnerabilities,
                                          Set<String> piiReported) {
        if (parameter == null || constraintAnalyzer == null) {
            return;
        }
        PiiSignal signal = SchemaPiiInspector.inspectParameter(parameter, constraintAnalyzer);
        reportPiiSignal(location, method, signal, vulnerabilities, piiReported);
    }

    private void reportPiiSignal(String location,
                                 String method,
                                 PiiSignal signal,
                                 List<Vulnerability> vulnerabilities,
                                 Set<String> piiReported) {
        if (signal == null) {
            return;
        }
        String key = location + "|" + signal.pointer();
        if (!piiReported.add(key)) {
            return;
        }
        Severity severity = signal.highRisk() ? Severity.HIGH : Severity.MEDIUM;
        if (location != null && location.toLowerCase(Locale.ROOT).contains("response")) {
            severity = severity == Severity.HIGH ? Severity.CRITICAL : Severity.HIGH;
        }
        int riskScore = severity == Severity.CRITICAL ? 95 : severity == Severity.HIGH ? 80 : 60;
        Vulnerability vulnerability = Vulnerability.builder()
            .id(VulnerabilityIdGenerator.generateId(
                VulnerabilityType.EXCESSIVE_DATA_EXPOSURE,
                location,
                method != null ? method : "N/A",
                signal.pointer(),
                "PII field detected"))
            .type(VulnerabilityType.EXCESSIVE_DATA_EXPOSURE)
            .severity(severity)
            .riskScore(riskScore)
            .confidence(signal.highRisk() ? 80 : 70)
            .priority(signal.highRisk() ? 2 : 3)
            .title("PII поле в спецификации")
            .description("Поле \"" + signal.pointer() + "\" описывает чувствительные данные (" + signal.reason() + "). Убедитесь, что спецификация не раскрывает реальные значения и снабжена пометками.")
            .endpoint(location)
            .method(method != null ? method : "N/A")
            .recommendation("Используйте плейсхолдеры вместо реальных персональных данных, добавьте masking и классификацию PII.")
            .owaspCategory("API3:2023 - Excessive Data Exposure")
            .evidence(signal.evidence())
            .build();
        vulnerabilities.add(vulnerability);
    }

    private Severity adjustSeverityForGuard(Severity base,
                                            SchemaConstraintAnalyzer.SchemaConstraints constraints) {
        if (constraints == null) {
            return base;
        }
        if (!constraints.isUserControlled()) {
            return base;
        }
        SchemaConstraintAnalyzer.SchemaConstraints.GuardStrength strength = constraints.getGuardStrength();
        if (strength == SchemaConstraintAnalyzer.SchemaConstraints.GuardStrength.STRONG) {
            return downgradeSeverity(base);
        }
        if (strength == SchemaConstraintAnalyzer.SchemaConstraints.GuardStrength.MODERATE && base.compareTo(Severity.MEDIUM) > 0) {
            return Severity.MEDIUM;
        }
        return base;
    }

    private int adjustConfidenceForGuard(int base,
                                         SchemaConstraintAnalyzer.SchemaConstraints constraints) {
        if (constraints == null) {
            return base;
        }
        if (!constraints.isUserControlled()) {
            return Math.min(100, base + 5);
        }
        SchemaConstraintAnalyzer.SchemaConstraints.GuardStrength strength = constraints.getGuardStrength();
        return switch (strength) {
            case STRONG -> Math.max(50, base - 25);
            case MODERATE -> Math.max(60, base - 15);
            case WEAK, NONE, NOT_USER_CONTROLLED -> base;
        };
    }

    private Severity downgradeSeverity(Severity severity) {
        return switch (severity) {
            case CRITICAL -> Severity.HIGH;
            case HIGH -> Severity.MEDIUM;
            case MEDIUM -> Severity.LOW;
            case LOW, INFO -> Severity.INFO;
        };
    }

    private void analyzeValue(String location,
                               String method,
                               Object value,
                               List<Vulnerability> vulnerabilities,
                               Set<String> reported) {
        if (value == null) {
            return;
        }
        Set<String> candidates = extractStringCandidates(value, 0);
        for (String candidate : candidates) {
            handleSecretCandidate(location, method, candidate, null, null, vulnerabilities, reported);
        }
    }

    private SecretMatch detectSecret(String candidate) {
        if (candidate == null) {
            return null;
        }
        String trimmed = candidate.trim();
        if (trimmed.length() < 8) {
            return null;
        }

        for (Pattern pattern : secretPatterns) {
            Matcher matcher = pattern.matcher(trimmed);
            if (matcher.find()) {
                Severity severity = trimmed.contains("PRIVATE KEY") ? Severity.CRITICAL : Severity.HIGH;
                return createSecretMatch(trimmed, severity, "Pattern match");
            }
        }

        String lower = trimmed.toLowerCase(Locale.ROOT);
        for (String indicator : secretIndicators) {
            if (indicator == null || indicator.isBlank()) {
                continue;
            }
            String keyword = indicator.toLowerCase(Locale.ROOT);
            if (lower.contains(keyword) && (lower.contains(":") || lower.contains("=") || lower.contains(" "))) {
                if (trimmed.length() >= 12 && hasLetterAndDigit(trimmed)) {
                    Severity severity = keyword.contains("private") || keyword.contains("secret") ? Severity.CRITICAL : Severity.HIGH;
                    return createSecretMatch(trimmed, severity, "Indicator " + indicator);
                }
            }
        }
        return null;
    }

    private boolean hasLetterAndDigit(String value) {
        boolean hasLetter = false;
        boolean hasDigit = false;
        for (char ch : value.toCharArray()) {
            if (Character.isLetter(ch)) {
                hasLetter = true;
            } else if (Character.isDigit(ch)) {
                hasDigit = true;
            }
            if (hasLetter && hasDigit) {
                return true;
            }
        }
        return false;
    }

    private SecretMatch createSecretMatch(String value, Severity severity, String label) {
        String masked = maskValue(value);
        int confidence = severity == Severity.CRITICAL ? 95 : 85;
        int priority = severity == Severity.CRITICAL ? 1 : 2;
        return new SecretMatch(severity, masked, label, confidence, priority);
    }

    private String maskValue(String value) {
        if (value == null || value.isEmpty()) {
            return "***";
        }
        String trimmed = value.trim();
        if (trimmed.length() <= 8) {
            return "***";
        }
        String prefix = trimmed.substring(0, 4);
        String suffix = trimmed.substring(trimmed.length() - 4);
        return prefix + "…" + suffix;
    }

    private Set<String> extractStringCandidates(Object value, int depth) {
        if (value == null || depth > 4) {
            return Collections.emptySet();
        }
        Set<String> results = new LinkedHashSet<>();
        if (value instanceof String str) {
            results.add(str);
        } else if (value instanceof Number || value instanceof Boolean) {
            results.add(String.valueOf(value));
        } else if (value instanceof Map<?, ?> map) {
            for (Object mapValue : map.values()) {
                results.addAll(extractStringCandidates(mapValue, depth + 1));
            }
        } else if (value instanceof Iterable<?> iterable) {
            for (Object item : iterable) {
                results.addAll(extractStringCandidates(item, depth + 1));
            }
        } else if (value instanceof Schema<?> schema) {
            collectSchemaSamples(schema, "schema").stream()
                .map(SchemaSample::value)
                .filter(Objects::nonNull)
                .forEach(results::add);
        } else {
            results.add(String.valueOf(value));
        }
        return results;
    }

    private List<SchemaSample> collectSchemaSamples(Schema<?> schema, String pointer) {
        List<SchemaSample> samples = new ArrayList<>();
        collectSchemaSamples(schema, pointer != null ? pointer : "schema", new LinkedHashSet<>(), samples);
        return samples;
    }

    private void collectSchemaSamples(Schema<?> schema,
                                      String pointer,
                                      Set<Schema<?>> visited,
                                      List<SchemaSample> samples) {
        if (schema == null || constraintAnalyzer == null || !visited.add(schema)) {
            return;
        }
        SchemaConstraintAnalyzer.SchemaConstraints constraints = constraintAnalyzer.analyzeSchema(schema);
        addSchemaValue(samples, schema.getExample(), pointer, constraints);
        addSchemaValue(samples, schema.getDefault(), pointer, constraints);
        addSchemaValue(samples, schema.getConst(), pointer, constraints);
        if (schema.getEnum() != null) {
            schema.getEnum().forEach(item -> addSchemaValue(samples, item, pointer, constraints));
        }
        if (schema.getProperties() != null) {
            schema.getProperties().forEach((name, value) -> {
                if (value instanceof Schema<?> child) {
                    String childPointer = pointer + "." + name;
                    collectSchemaSamples(child, childPointer, new LinkedHashSet<>(visited), samples);
                }
            });
        }
        if (schema.getAllOf() != null) {
            schema.getAllOf().forEach(sub ->
                collectSchemaSamples(sub, pointer, new LinkedHashSet<>(visited), samples));
        }
        if (schema.getOneOf() != null) {
            int index = 0;
            for (Schema<?> sub : schema.getOneOf()) {
                collectSchemaSamples(sub, pointer + ".oneOf[" + index + "]", new LinkedHashSet<>(visited), samples);
                index++;
            }
        }
        if (schema.getAnyOf() != null) {
            int index = 0;
            for (Schema<?> sub : schema.getAnyOf()) {
                collectSchemaSamples(sub, pointer + ".anyOf[" + index + "]", new LinkedHashSet<>(visited), samples);
                index++;
            }
        }
        if (schema.getItems() != null) {
            collectSchemaSamples(schema.getItems(), pointer + "[]", new LinkedHashSet<>(visited), samples);
        }
        if (schema.getAdditionalProperties() instanceof Schema<?>) {
            collectSchemaSamples((Schema<?>) schema.getAdditionalProperties(), pointer + ".{}", new LinkedHashSet<>(visited), samples);
        }
    }

    private void addSchemaValue(List<SchemaSample> samples,
                                Object value,
                                String pointer,
                                SchemaConstraintAnalyzer.SchemaConstraints constraints) {
        if (value == null) {
            return;
        }
        samples.add(new SchemaSample(String.valueOf(value), constraints, pointer));
    }

    private List<Operation> collectOperations(PathItem pathItem) {
        List<Operation> operations = new ArrayList<>();
        if (pathItem.getGet() != null) operations.add(pathItem.getGet());
        if (pathItem.getPost() != null) operations.add(pathItem.getPost());
        if (pathItem.getPut() != null) operations.add(pathItem.getPut());
        if (pathItem.getDelete() != null) operations.add(pathItem.getDelete());
        if (pathItem.getPatch() != null) operations.add(pathItem.getPatch());
        if (pathItem.getOptions() != null) operations.add(pathItem.getOptions());
        if (pathItem.getHead() != null) operations.add(pathItem.getHead());
        return operations;
    }

    private List<Pattern> compilePatterns(List<String> patterns) {
        List<Pattern> compiled = new ArrayList<>();
        if (patterns != null) {
            for (String pattern : patterns) {
                if (pattern != null && !pattern.isBlank()) {
                    compiled.add(Pattern.compile(pattern, Pattern.MULTILINE));
                }
            }
        }
        return compiled;
    }

    private List<String> defaultSecretPatterns() {
        return List.of(
            "(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
            "(?i)AKIA[0-9A-Z]{16}",
            "(?i)(?:api|auth|access|client|secret)[-_]?(?:key|token|secret)\\s*[:=]\\s*[\"']?[A-Za-z0-9\\-_/+=]{12,}",
            "(?i)password\\s*[:=]\\s*[\"']?[A-Za-z0-9@#$%^&*()_+\\-=]{6,}"
        );
    }

    private List<String> defaultSecretIndicators() {
        return List.of("token", "secret", "password", "pwd", "bearer", "api_key", "client_secret", "private_key", "access-key");
    }

    private List<String> defaultShadowKeywords() {
        return List.of("dev", "test", "qa", "stage", "staging", "preprod", "sandbox", "uat", "localhost", "127.0.0.1");
    }

    private record SchemaSample(String value,
                                SchemaConstraintAnalyzer.SchemaConstraints constraints,
                                String pointer) {}

    private record SecretMatch(Severity severity, String maskedPreview, String label, int confidence, int priority) {}
}
