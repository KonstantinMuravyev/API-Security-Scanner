package com.vtb.scanner.scanners;

import com.vtb.scanner.analysis.SchemaConstraintAnalyzer;
import com.vtb.scanner.analysis.SchemaConstraintAnalyzer.SchemaConstraints;
import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.regex.Pattern;

/**
 * API7:2023 - Server Side Request Forgery (SSRF)
 * Проверяет параметры, которые могут использоваться для SSRF атак
 */
@Slf4j
public class SSRFScanner implements VulnerabilityScanner {
    
    private final String targetUrl;
    
    // Паттерны опасных параметров для SSRF
    private static final Pattern SSRF_PATTERN = Pattern.compile(
        ".*(url|uri|link|href|redirect|callback|webhook|proxy|fetch|download|import|source|src).*",
        Pattern.CASE_INSENSITIVE
    );
    
    public SSRFScanner(String targetUrl) {
        this.targetUrl = targetUrl;
    }
    
    @Override
    public List<Vulnerability> scan(OpenAPI openAPI, OpenAPIParser parser) {
        log.info("Запуск SSRF Scanner (API7:2023) для {}...", targetUrl);
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        SchemaConstraintAnalyzer constraintAnalyzer = new SchemaConstraintAnalyzer(openAPI);

        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            if (pathItem.getGet() != null) {
                vulnerabilities.addAll(checkSSRF(path, "GET", pathItem.getGet(), openAPI, constraintAnalyzer));
            }
            if (pathItem.getPost() != null) {
                vulnerabilities.addAll(checkSSRF(path, "POST", pathItem.getPost(), openAPI, constraintAnalyzer));
            }
            if (pathItem.getPut() != null) {
                vulnerabilities.addAll(checkSSRF(path, "PUT", pathItem.getPut(), openAPI, constraintAnalyzer));
            }
            if (pathItem.getPatch() != null) {
                vulnerabilities.addAll(checkSSRF(path, "PATCH", pathItem.getPatch(), openAPI, constraintAnalyzer));
            }
        }
        
        log.info("SSRF Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkSSRF(String path, String method, Operation operation, OpenAPI openAPI,
                                          SchemaConstraintAnalyzer constraintAnalyzer) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // ИСПОЛЬЗУЕМ SmartAnalyzer для контекста!
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
            path, method, operation, openAPI);
        Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
        
        // СЕМАНТИКА: определяем тип операции
        com.vtb.scanner.semantic.OperationClassifier.OperationType opType = 
            com.vtb.scanner.semantic.OperationClassifier.classify(path, method, operation);
        com.vtb.scanner.semantic.ContextAnalyzer.APIContext apiContext =
            openAPI != null ? com.vtb.scanner.semantic.ContextAnalyzer.detectContext(openAPI) :
                com.vtb.scanner.semantic.ContextAnalyzer.APIContext.GENERAL;

        boolean hasAllowList = hasAllowListEvidence(operation);
        boolean warnsInternal = warnsInternalNetworks(operation);

        List<SSRFField> ssrfFields = new ArrayList<>();

        if (operation.getParameters() != null) {
            for (Parameter param : operation.getParameters()) {
                if (param == null) {
                    continue;
                }
                SchemaConstraints constraints = constraintAnalyzer != null
                    ? constraintAnalyzer.analyzeParameter(param)
                    : null;
                if (com.vtb.scanner.heuristics.EnhancedRules.isSSRFRisk(param, constraints)) {
                    ssrfFields.add(SSRFField.fromParameter(param, constraints));
                }
            }
        }

        ssrfFields.addAll(collectBodyFields(operation, openAPI, constraintAnalyzer));

        if (ssrfFields.isEmpty()) {
            return vulnerabilities;
        }
        
        for (SSRFField field : ssrfFields) {
            boolean hasValidation = field.hasValidation();

            Severity severity = calculateSeverity(baseSeverity, opType, apiContext, riskScore, hasValidation, hasAllowList, warnsInternal);

            Vulnerability tempVuln = Vulnerability.builder()
                .type(VulnerabilityType.SSRF)
                .severity(severity)
                .riskScore(riskScore)
                .build();

            int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                tempVuln, operation, false, true);
            if (hasValidation) {
                confidence = Math.max(50, confidence - 20);
            }
            if (hasAllowList) {
                confidence = Math.max(40, confidence - 10);
            }

            int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(tempVuln, confidence);

            Vulnerability vuln = Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.SSRF, path, method, field.name,
                    "SSRF risk in " + field.location))
                .type(VulnerabilityType.SSRF)
                .severity(severity)
                .title("Возможна SSRF уязвимость")
                .description(buildDescription(field, method, path, opType, hasValidation, hasAllowList, warnsInternal))
                .endpoint(path)
                .method(method)
                .recommendation(buildRecommendation(hasAllowList, apiContext))
                .owaspCategory("API7:2023 - Server Side Request Forgery")
                .evidence(field.evidence())
                .confidence(confidence)
                .priority(priority)
                .impactLevel(determineImpact(opType, apiContext))
                .riskScore(riskScore)
                .build();

            if (!field.applySchemaGuards(vuln)) {
                continue;
            }

            vulnerabilities.add(vuln);
        }
        
        return vulnerabilities;
    }
    
    private Severity calculateSeverity(Severity baseSeverity,
                                       com.vtb.scanner.semantic.OperationClassifier.OperationType opType,
                                       com.vtb.scanner.semantic.ContextAnalyzer.APIContext apiContext,
                                       int riskScore,
                                       boolean hasValidation,
                                       boolean hasAllowList,
                                       boolean warnsInternal) {
        boolean criticalContext = apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.BANKING ||
            apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.GOVERNMENT ||
            apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.HEALTHCARE ||
            apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.TELECOM ||
            apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.AUTOMOTIVE;

        Severity severity;
        if (opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.ADMIN_ACTION) {
            severity = (baseSeverity == Severity.CRITICAL || riskScore > 120 || warnsInternal) ?
                Severity.CRITICAL : Severity.HIGH;
        } else {
            severity = switch (baseSeverity) {
                case INFO, LOW -> hasValidation ? Severity.LOW : Severity.MEDIUM;
                case MEDIUM -> hasValidation ? Severity.MEDIUM : Severity.HIGH;
                case HIGH, CRITICAL -> hasValidation ? Severity.MEDIUM : baseSeverity;
            };
        }

        if (criticalContext && severity.compareTo(Severity.CRITICAL) < 0) {
            severity = Severity.HIGH;
        }
        if (hasAllowList && severity.compareTo(Severity.MEDIUM) > 0) {
            severity = Severity.MEDIUM;
        }
        return severity;
    }

    private String buildDescription(SSRFField field,
                                    String method,
                                    String path,
                                    com.vtb.scanner.semantic.OperationClassifier.OperationType opType,
                                    boolean hasValidation,
                                    boolean hasAllowList,
                                    boolean warnsInternal) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%s '%s' в %s %s принимает URL / внешний ресурс. Тип операции: %s.",
            field.locationLabel(), field.name, method, path, opType));
        if (field.inRequestBody()) {
            sb.append(" Поле обнаружено в request body (" + field.path + ").");
        }
        if (hasValidation) {
            sb.append(" Найдена базовая валидация (format/pattern), но этого недостаточно для предотвращения SSRF.");
        } else {
            sb.append(" Не обнаружено ограничений или whitelist для значения.");
        }
        if (hasAllowList) {
            sb.append(" В описании упомянут whitelist, но убедитесь, что он строго применён.");
        }
        if (!warnsInternal) {
            sb.append(" Добавьте явные запреты на обращения к localhost, приватным IP и AWS metadata.");
        }
        return sb.toString();
    }

    private String buildRecommendation(boolean hasAllowList,
                                       com.vtb.scanner.semantic.ContextAnalyzer.APIContext apiContext) {
        StringBuilder sb = new StringBuilder();
        sb.append("1. Ограничьте протоколы (только http/https) и используйте whitelist доменов.\n");
        sb.append("2. Блокируйте localhost, 127.0.0.1, 169.254.169.254, приватные IP, файловые протоколы.\n");
        sb.append("3. Валидируйте URL и выполняйте DNS rebinding защиту.\n");
        if (apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.TELECOM ||
            apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.AUTOMOTIVE) {
            sb.append("4. Для TELECOM/Connected-Car сервисов добавьте фильтрацию на внутренние API и телематические хабы.\n");
        }
        if (!hasAllowList) {
            sb.append("5. Реализуйте централизованный whitelist доменов, управляемый через конфигурацию.");
        }
        return sb.toString();
    }

    private String determineImpact(com.vtb.scanner.semantic.OperationClassifier.OperationType opType,
                                   com.vtb.scanner.semantic.ContextAnalyzer.APIContext apiContext) {
        if (opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.ADMIN_ACTION) {
            return "PRIVILEGE_ESCALATION: SSRF через админ функционал";
        }
        if (apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.BANKING) {
            return "FINANCIAL_FRAUD: SSRF для доступа к платежным системам";
        }
        if (apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.TELECOM) {
            return "TELECOM_OUTAGE: SSRF для доступа к внутренним биллинговым системам";
        }
        if (apiContext == com.vtb.scanner.semantic.ContextAnalyzer.APIContext.AUTOMOTIVE) {
            return "CONNECTED_CAR: SSRF к телематическим шлюзам";
        }
        return "SYSTEM_ACCESS: Доступ к внутренним системам";
    }

    private boolean hasAllowListEvidence(Operation operation) {
        if (operation == null) {
            return false;
        }
        String text = combineText(operation);
        return text.contains("allowlist") || text.contains("whitelist") || text.contains("trusted host") ||
            text.contains("allowed domains") || text.contains("разрешенные домены") || text.contains("разрешенный хост");
    }

    private boolean warnsInternalNetworks(Operation operation) {
        if (operation == null) {
            return false;
        }
        String text = combineText(operation);
        return text.contains("localhost") || text.contains("127.0.0.1") || text.contains("169.254.169.254") ||
            text.contains("metadata") || text.contains("aws") || text.contains("внутренний ip");
    }

    private String combineText(Operation operation) {
        StringBuilder sb = new StringBuilder();
        if (operation.getSummary() != null) {
            sb.append(operation.getSummary().toLowerCase(Locale.ROOT)).append(' ');
        }
        if (operation.getDescription() != null) {
            sb.append(operation.getDescription().toLowerCase(Locale.ROOT)).append(' ');
        }
        return sb.toString();
    }

    private List<SSRFField> collectBodyFields(Operation operation, OpenAPI openAPI,
                                             SchemaConstraintAnalyzer constraintAnalyzer) {
        List<SSRFField> fields = new ArrayList<>();
        if (operation == null || operation.getRequestBody() == null || operation.getRequestBody().getContent() == null) {
            return fields;
        }

        operation.getRequestBody().getContent().forEach((contentType, mediaType) -> {
            if (mediaType == null || mediaType.getSchema() == null) {
                return;
            }
            collectFromSchema(mediaType.getSchema(), openAPI, constraintAnalyzer, new HashSet<>(), "$", fields);
        });
        return fields;
    }

    private void collectFromSchema(io.swagger.v3.oas.models.media.Schema<?> schema,
                                   OpenAPI openAPI,
                                   SchemaConstraintAnalyzer constraintAnalyzer,
                                   Set<String> visited,
                                   String path,
                                   List<SSRFField> fields) {
        if (schema == null) {
            return;
        }
        if (schema.get$ref() != null) {
            String ref = schema.get$ref();
            if (!visited.add(ref)) {
                return;
            }
            io.swagger.v3.oas.models.media.Schema<?> resolved = resolveSchema(ref, openAPI);
            collectFromSchema(resolved, openAPI, constraintAnalyzer, visited, path, fields);
            return;
        }

        if (schema.getProperties() != null) {
            Map<String, ?> properties = schema.getProperties();
            for (Map.Entry<String, ?> entry : properties.entrySet()) {
                String name = entry.getKey();
                io.swagger.v3.oas.models.media.Schema<?> propertySchema = entry.getValue() instanceof io.swagger.v3.oas.models.media.Schema<?> ?
                    (io.swagger.v3.oas.models.media.Schema<?>) entry.getValue() : null;
                String propertyPath = path + "." + name;
                if (propertySchema != null) {
                    SchemaConstraints constraints = constraintAnalyzer != null
                        ? constraintAnalyzer.analyzeSchema(propertySchema)
                        : null;
                    if (isSsrfSchema(name, propertySchema) && !SchemaConstraints.GuardStrength.STRONG.equals(
                        constraints != null ? constraints.getGuardStrength() : null)) {
                        fields.add(SSRFField.fromSchema(name, propertyPath, propertySchema, constraints));
                    }
                    collectFromSchema(propertySchema, openAPI, constraintAnalyzer, visited, propertyPath, fields);
                }
            }
        }

        if (schema.getItems() != null) {
            collectFromSchema(schema.getItems(), openAPI, constraintAnalyzer, visited, path + "[]", fields);
        }
    }

    private boolean isSsrfSchema(String name, io.swagger.v3.oas.models.media.Schema<?> schema) {
        String lowerName = name != null ? name.toLowerCase(Locale.ROOT) : "";
        if (SSRF_PATTERN.matcher(lowerName).matches()) {
            return true;
        }
        String format = schema.getFormat();
        if (format != null && (format.equalsIgnoreCase("uri") || format.equalsIgnoreCase("url"))) {
            return true;
        }
        String pattern = schema.getPattern();
        if (pattern != null && pattern.contains("http")) {
            return true;
        }
        return false;
    }

    private io.swagger.v3.oas.models.media.Schema<?> resolveSchema(String ref, OpenAPI openAPI) {
        if (openAPI == null || ref == null || !ref.startsWith("#/components/schemas/")) {
            return null;
        }
        String name = ref.substring("#/components/schemas/".length());
        if (openAPI.getComponents() != null && openAPI.getComponents().getSchemas() != null) {
            return openAPI.getComponents().getSchemas().get(name);
        }
        return null;
    }

    private static class SSRFField {
        final String name;
        final String location;
        final String path;
        final io.swagger.v3.oas.models.media.Schema<?> schema;
        final SchemaConstraints constraints;

        private SSRFField(String name, String location, String path,
                          io.swagger.v3.oas.models.media.Schema<?> schema,
                          SchemaConstraints constraints) {
            this.name = name != null ? name : "n/a";
            this.location = location;
            this.path = path;
            this.schema = schema;
            this.constraints = constraints;
        }

        static SSRFField fromParameter(Parameter parameter, SchemaConstraints constraints) {
            return new SSRFField(parameter.getName(), parameter.getIn(), parameter.getName(), parameter.getSchema(), constraints);
        }

        static SSRFField fromSchema(String name, String path,
                                    io.swagger.v3.oas.models.media.Schema<?> schema,
                                    SchemaConstraints constraints) {
            return new SSRFField(name, "body", path, schema, constraints);
        }

        boolean hasValidation() {
            if (schema == null) {
                return false;
            }
            String format = schema.getFormat();
            String pattern = schema.getPattern();
            return (format != null && (format.equalsIgnoreCase("uri") || format.equalsIgnoreCase("url"))) ||
                (pattern != null && !pattern.isEmpty());
        }

        boolean inRequestBody() {
            return "body".equals(location);
        }

        String locationLabel() {
            return inRequestBody() ? "Поле" : "Параметр";
        }

        String evidence() {
            StringBuilder sb = new StringBuilder();
            sb.append(locationLabel()).append(" '").append(name).append("'");
            if (inRequestBody()) {
                sb.append(" (" + path + ")");
            }
            if (schema != null) {
                if (schema.getFormat() != null) {
                    sb.append(" format=").append(schema.getFormat());
                }
                if (schema.getPattern() != null) {
                    sb.append(" pattern=").append(schema.getPattern());
                }
            }
            if (constraints != null && constraints.buildEvidenceNote() != null) {
                sb.append(" ").append(constraints.buildEvidenceNote());
            }
            return sb.toString();
        }

        boolean applySchemaGuards(Vulnerability vulnerability) {
            if (constraints == null) {
                return true;
            }
            if (!com.vtb.scanner.heuristics.EnhancedRules.isGuardLikelySafe(constraints)) {
                String note = constraints.buildEvidenceNote();
                if (note != null) {
                    String existing = vulnerability.getEvidence();
                    if (existing == null || !existing.contains(note)) {
                        vulnerability.setEvidence(existing == null ? note : existing + "; " + note);
                    }
                }
                return true;
            }
            return false;
        }
    }
}

