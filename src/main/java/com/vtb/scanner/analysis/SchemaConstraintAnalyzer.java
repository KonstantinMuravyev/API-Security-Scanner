package com.vtb.scanner.analysis;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Анализ ограничений входных данных, заданных в схемах OpenAPI.
 */
public class SchemaConstraintAnalyzer {

    private final OpenAPI openAPI;

    public SchemaConstraintAnalyzer(OpenAPI openAPI) {
        this.openAPI = openAPI;
    }

    /**
     * Анализирует ограничения конкретного параметра (query/path/header/cookie).
     */
    public SchemaConstraints analyzeParameter(Parameter parameter) {
        if (parameter == null) {
            return SchemaConstraints.empty();
        }

        Schema<?> schema = parameter.getSchema();
        if (schema == null && parameter.getContent() != null) {
            for (io.swagger.v3.oas.models.media.MediaType mediaType : parameter.getContent().values()) {
                if (mediaType != null && mediaType.getSchema() != null) {
                    schema = mediaType.getSchema();
                    break;
                }
            }
        }
        if (schema == null) {
            return SchemaConstraints.empty();
        }

        SchemaConstraints constraints = analyzeSchema(schema);
        if (!Boolean.TRUE.equals(parameter.getRequired())) {
            constraints = constraints.withOptional();
        }
        return constraints;
    }

    /**
     * Анализирует ограничения произвольной схемы (в т.ч. для request body).
     */
    public SchemaConstraints analyzeSchema(Schema<?> schema) {
        return analyzeSchemaInternal(schema, new LinkedHashSet<>());
    }

    private SchemaConstraints analyzeSchemaInternal(Schema<?> schema, Set<String> visited) {
        if (schema == null) {
            return SchemaConstraints.empty();
        }

        Schema<?> resolved = resolveReference(schema, visited);
        if (resolved == null) {
            return SchemaConstraints.empty();
        }

        SchemaConstraints.Builder builder = SchemaConstraints.builder();
        collectSchemaAttributes(builder, resolved);

        if (resolved.getAllOf() != null) {
            for (Schema<?> subSchema : resolved.getAllOf()) {
                if (subSchema == null) {
                    continue;
                }
                SchemaConstraints subConstraints = analyzeSchemaInternal(subSchema, new LinkedHashSet<>(visited));
                builder.addAllOfConstraint(subConstraints);
                mergeAllOf(builder, subSchema, subConstraints, visited);
            }
        }

        if (resolved.getOneOf() != null) {
            for (Schema<?> subSchema : resolved.getOneOf()) {
                if (subSchema == null) {
                    continue;
                }
                SchemaConstraints subConstraints = analyzeSchemaInternal(subSchema, new LinkedHashSet<>(visited));
                builder.addOneOfConstraint(subConstraints);
            }
        }

        if (resolved.getAnyOf() != null) {
            for (Schema<?> subSchema : resolved.getAnyOf()) {
                if (subSchema == null) {
                    continue;
                }
                SchemaConstraints subConstraints = analyzeSchemaInternal(subSchema, new LinkedHashSet<>(visited));
                builder.addAnyOfConstraint(subConstraints);
            }
        }

        if ("array".equals(builder.getType()) || resolved.getItems() != null) {
            Schema<?> itemsSchema = resolved.getItems();
            if (itemsSchema != null) {
                builder.itemsConstraints(analyzeSchemaInternal(itemsSchema, new LinkedHashSet<>(visited)));
            } else if (resolved.getProperties() == null && resolved.getOneOf() != null) {
                // array may be defined via oneOf items on sub-schemas; handled by variants already
            }
        }

        return builder.build();
    }

    private void collectSchemaAttributes(SchemaConstraints.Builder builder, Schema<?> schema) {
        if (schema == null) {
            return;
        }

        String type = normalize(schema.getType());
        if (type == null) {
            if (schema.getProperties() != null) {
                type = "object";
            } else if (schema.getItems() != null) {
                type = "array";
            }
        }
        if (type != null) {
            if (builder.getType() == null) {
                builder.type(type);
            }
        }

        String format = normalize(schema.getFormat());
        if (format != null && builder.getFormat() == null) {
            builder.format(format);
        }

        if (Boolean.TRUE.equals(schema.getNullable())) {
            builder.nullable(true);
        }
        if (Boolean.TRUE.equals(schema.getReadOnly())) {
            builder.readOnly(true);
        }
        if (Boolean.TRUE.equals(schema.getWriteOnly())) {
            builder.writeOnly(true);
        }
        if (Boolean.TRUE.equals(schema.getDeprecated())) {
            builder.deprecated(true);
        }

        if (schema.getPattern() != null && builder.getPattern() == null) {
            builder.pattern(trimToNull(schema.getPattern()));
        }

        if (schema.getMinLength() != null) {
            Integer current = builder.getMinLength();
            if (current == null || schema.getMinLength() > current) {
                builder.minLength(schema.getMinLength());
            }
        }

        if (schema.getMaxLength() != null) {
            Integer current = builder.getMaxLength();
            if (current == null || schema.getMaxLength() < current) {
                builder.maxLength(schema.getMaxLength());
            }
        }

        if (schema.getMinimum() != null) {
            BigDecimal minimum = asBigDecimal(schema.getMinimum());
            BigDecimal current = builder.getMinimum();
            if (current == null || (minimum != null && minimum.compareTo(current) > 0)) {
                builder.minimum(minimum);
                builder.exclusiveMinimum(Boolean.TRUE.equals(schema.getExclusiveMinimum()));
            }
        } else if (Boolean.TRUE.equals(schema.getExclusiveMinimum())) {
            builder.exclusiveMinimum(true);
        }

        if (schema.getMaximum() != null) {
            BigDecimal maximum = asBigDecimal(schema.getMaximum());
            BigDecimal current = builder.getMaximum();
            if (current == null || (maximum != null && maximum.compareTo(current) < 0)) {
                builder.maximum(maximum);
                builder.exclusiveMaximum(Boolean.TRUE.equals(schema.getExclusiveMaximum()));
            }
        } else if (Boolean.TRUE.equals(schema.getExclusiveMaximum())) {
            builder.exclusiveMaximum(true);
        }

        if (schema.getConst() != null) {
            builder.constValue(objectToString(schema.getConst()));
        }

        if (schema.getDefault() != null && builder.getDefaultValue() == null) {
            builder.defaultValue(objectToString(schema.getDefault()));
        }

        List<String> enumValues = toStringList(schema.getEnum());
        if (!enumValues.isEmpty()) {
            List<String> current = builder.getEnumValues();
            if (current == null || current.isEmpty()) {
                builder.enumValues(enumValues);
            } else {
                List<String> intersection = new ArrayList<>();
                for (String value : current) {
                    if (enumValues.contains(value)) {
                        intersection.add(value);
                    }
                }
                if (!intersection.isEmpty()) {
                    builder.enumValues(intersection);
                }
            }
        }

        if (schema.getItems() != null && (builder.getType() == null || "array".equals(builder.getType()))) {
            builder.type("array");
        }
    }

    private void mergeAllOf(SchemaConstraints.Builder builder,
                            Schema<?> rawSchema,
                            SchemaConstraints constraints,
                            Set<String> visited) {
        if (rawSchema == null) {
            return;
        }
        Schema<?> resolved = resolveReference(rawSchema, new LinkedHashSet<>(visited));
        collectSchemaAttributes(builder, resolved);

        if (constraints != null) {
            if (constraints.getType() != null && builder.getType() == null) {
                builder.type(constraints.getType());
            }
            if (constraints.getFormat() != null && builder.getFormat() == null) {
                builder.format(constraints.getFormat());
            }
            if (constraints.isNullable()) {
                builder.nullable(true);
            }
            if (constraints.isReadOnly()) {
                builder.readOnly(true);
            }
            if (constraints.isWriteOnly()) {
                builder.writeOnly(true);
            }

            Integer minLength = constraints.getMinLength();
            if (minLength != null) {
                Integer current = builder.getMinLength();
                if (current == null || minLength > current) {
                    builder.minLength(minLength);
                }
            }

            Integer maxLength = constraints.getMaxLength();
            if (maxLength != null) {
                Integer current = builder.getMaxLength();
                if (current == null || maxLength < current) {
                    builder.maxLength(maxLength);
                }
            }

            BigDecimal minimum = constraints.getMinimum();
            if (minimum != null) {
                BigDecimal current = builder.getMinimum();
                if (current == null || minimum.compareTo(current) > 0) {
                    builder.minimum(minimum);
                    builder.exclusiveMinimum(constraints.isExclusiveMinimum());
                }
            }

            BigDecimal maximum = constraints.getMaximum();
            if (maximum != null) {
                BigDecimal current = builder.getMaximum();
                if (current == null || maximum.compareTo(current) < 0) {
                    builder.maximum(maximum);
                    builder.exclusiveMaximum(constraints.isExclusiveMaximum());
                }
            }

            if (constraints.getConstValue() != null) {
                builder.constValue(constraints.getConstValue());
            }

            if (constraints.getDefaultValue() != null && builder.getDefaultValue() == null) {
                builder.defaultValue(constraints.getDefaultValue());
            }

            List<String> enumValues = constraints.getEnumValues();
            if (enumValues != null && !enumValues.isEmpty()) {
                List<String> current = builder.getEnumValues();
                if (current == null || current.isEmpty()) {
                    builder.enumValues(enumValues);
                } else {
                    List<String> intersection = new ArrayList<>();
                    for (String value : current) {
                        if (enumValues.contains(value)) {
                            intersection.add(value);
                        }
                    }
                    if (!intersection.isEmpty()) {
                        builder.enumValues(intersection);
                    }
                }
            }
        }
    }

    private Schema<?> resolveReference(Schema<?> schema, Set<String> visited) {
        if (schema == null || schema.get$ref() == null || openAPI == null || openAPI.getComponents() == null) {
            return schema;
        }

        String ref = schema.get$ref();
        if (!ref.startsWith("#/components/schemas/")) {
            return schema;
        }

        String name = ref.substring("#/components/schemas/".length());
        if (!visited.add(name)) {
            return schema; // защита от циклов
        }

        Map<String, Schema> schemas = openAPI.getComponents().getSchemas();
        if (schemas == null) {
            return schema;
        }

        Schema<?> resolved = schemas.get(name);
        if (resolved == null) {
            return schema;
        }

        return resolveReference(resolved, visited);
    }

    private static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed.toLowerCase();
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static BigDecimal asBigDecimal(Number number) {
        if (number == null) {
            return null;
        }
        if (number instanceof BigDecimal) {
            return (BigDecimal) number;
        }
        return new BigDecimal(number.toString());
    }

    private static String objectToString(Object value) {
        return value != null ? value.toString() : null;
    }

    private static List<String> toStringList(List<?> values) {
        if (values == null || values.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> result = new ArrayList<>();
        for (Object value : values) {
            if (value != null) {
                result.add(value.toString());
            }
        }
        return result;
    }

    /**
     * Информация о найденных ограничениях.
     */
    public static final class SchemaConstraints {

        public enum GuardStrength {
            NONE,
            WEAK,
            MODERATE,
            STRONG,
            NOT_USER_CONTROLLED
        }

        private final String type;
        private final String format;
        private final boolean nullable;
        private final boolean readOnly;
        private final boolean writeOnly;
        private final boolean deprecated;
        private final boolean optional;
        private final List<String> enumValues;
        private final String pattern;
        private final Integer minLength;
        private final Integer maxLength;
        private final BigDecimal minimum;
        private final BigDecimal maximum;
        private final boolean exclusiveMinimum;
        private final boolean exclusiveMaximum;
        private final String constValue;
        private final String defaultValue;
        private final SchemaConstraints itemsConstraints;
        private final GuardStrength guardStrength;
        private final List<String> guardDetails;
        private final List<SchemaConstraints> allOfConstraints;
        private final List<SchemaConstraints> anyOfConstraints;
        private final List<SchemaConstraints> oneOfConstraints;

        private SchemaConstraints(Builder builder) {
            this.type = builder.type;
            this.format = builder.format;
            this.nullable = builder.nullable;
            this.readOnly = builder.readOnly;
            this.writeOnly = builder.writeOnly;
            this.deprecated = builder.deprecated;
            this.optional = builder.optional;
            this.enumValues = builder.enumValues != null
                ? Collections.unmodifiableList(new ArrayList<>(builder.enumValues))
                : Collections.emptyList();
            this.pattern = builder.pattern;
            this.minLength = builder.minLength;
            this.maxLength = builder.maxLength;
            this.minimum = builder.minimum;
            this.maximum = builder.maximum;
            this.exclusiveMinimum = builder.exclusiveMinimum;
            this.exclusiveMaximum = builder.exclusiveMaximum;
            this.constValue = builder.constValue;
            this.defaultValue = builder.defaultValue;
            this.itemsConstraints = builder.itemsConstraints;
            this.guardStrength = builder.guardStrength;
            this.guardDetails = Collections.unmodifiableList(new ArrayList<>(builder.guardDetails));
            this.allOfConstraints = Collections.unmodifiableList(new ArrayList<>(builder.allOfConstraints));
            this.anyOfConstraints = Collections.unmodifiableList(new ArrayList<>(builder.anyOfConstraints));
            this.oneOfConstraints = Collections.unmodifiableList(new ArrayList<>(builder.oneOfConstraints));
        }

        public static SchemaConstraints empty() {
            return builder().build();
        }

        public SchemaConstraints withOptional() {
            if (optional) {
                return this;
            }
            return toBuilder().optional(true).build();
        }

        private Builder toBuilder() {
            return builder()
                .type(type)
                .format(format)
                .nullable(nullable)
                .readOnly(readOnly)
                .writeOnly(writeOnly)
                .deprecated(deprecated)
                .optional(optional)
                .enumValues(enumValues)
                .pattern(pattern)
                .minLength(minLength)
                .maxLength(maxLength)
                .minimum(minimum)
                .maximum(maximum)
                .exclusiveMinimum(exclusiveMinimum)
                .exclusiveMaximum(exclusiveMaximum)
                .constValue(constValue)
                .defaultValue(defaultValue)
                .itemsConstraints(itemsConstraints)
                .allOfConstraints(allOfConstraints)
                .anyOfConstraints(anyOfConstraints)
                .oneOfConstraints(oneOfConstraints);
        }

        public String getType() {
            return type;
        }

        public boolean isUserControlled() {
            return guardStrength != GuardStrength.NOT_USER_CONTROLLED;
        }

        public GuardStrength getGuardStrength() {
            return guardStrength;
        }

        public List<String> getGuardDetails() {
            return guardDetails;
        }

        public String getFormat() {
            return format;
        }

        public boolean isNullable() {
            return nullable;
        }

        public boolean isReadOnly() {
            return readOnly;
        }

        public boolean isWriteOnly() {
            return writeOnly;
        }

        public boolean isExclusiveMinimum() {
            return exclusiveMinimum;
        }

        public boolean isExclusiveMaximum() {
            return exclusiveMaximum;
        }

        public Integer getMinLength() {
            return minLength;
        }

        public Integer getMaxLength() {
            return maxLength;
        }

        public String getPattern() {
            return pattern;
        }

        public BigDecimal getMinimum() {
            return minimum;
        }

        public BigDecimal getMaximum() {
            return maximum;
        }

        public String getConstValue() {
            return constValue;
        }

        public String getDefaultValue() {
            return defaultValue;
        }

        public List<String> getEnumValues() {
            return enumValues;
        }

        public SchemaConstraints getItemsConstraints() {
            return itemsConstraints;
        }

        public List<SchemaConstraints> getAllOfConstraints() {
            return allOfConstraints;
        }

        public List<SchemaConstraints> getAnyOfConstraints() {
            return anyOfConstraints;
        }

        public List<SchemaConstraints> getOneOfConstraints() {
            return oneOfConstraints;
        }

        public String buildEvidenceNote() {
            if (guardDetails.isEmpty()) {
                return null;
            }
            return "Schema guard: " + String.join(", ", guardDetails);
        }

        public static Builder builder() {
            return new Builder();
        }

        public static final class Builder {
            private String type;
            private String format;
            private boolean nullable;
            private boolean readOnly;
            private boolean writeOnly;
            private boolean deprecated;
            private boolean optional;
            private List<String> enumValues;
            private String pattern;
            private Integer minLength;
            private Integer maxLength;
            private BigDecimal minimum;
            private BigDecimal maximum;
            private boolean exclusiveMinimum;
            private boolean exclusiveMaximum;
            private String constValue;
            private String defaultValue;
            private SchemaConstraints itemsConstraints;

            private GuardStrength guardStrength = GuardStrength.NONE;
            private final List<String> guardDetails = new ArrayList<>();
            private final List<SchemaConstraints> allOfConstraints = new ArrayList<>();
            private final List<SchemaConstraints> anyOfConstraints = new ArrayList<>();
            private final List<SchemaConstraints> oneOfConstraints = new ArrayList<>();

            public Builder type(String type) {
                this.type = type;
                return this;
            }

            public String getType() {
                return type;
            }

            public String getFormat() {
                return format;
            }

            public Builder format(String format) {
                this.format = format;
                return this;
            }

            public Builder nullable(boolean nullable) {
                this.nullable = nullable;
                return this;
            }

            public boolean isReadOnly() {
                return readOnly;
            }

            public Builder readOnly(boolean readOnly) {
                this.readOnly = readOnly;
                return this;
            }

            public boolean isWriteOnly() {
                return writeOnly;
            }

            public Builder writeOnly(boolean writeOnly) {
                this.writeOnly = writeOnly;
                return this;
            }

            public Builder deprecated(boolean deprecated) {
                this.deprecated = deprecated;
                return this;
            }

            public Builder optional(boolean optional) {
                this.optional = optional;
                return this;
            }

            public Builder enumValues(List<String> enumValues) {
                if (enumValues != null) {
                    this.enumValues = new ArrayList<>(enumValues);
                }
                return this;
            }

            public List<String> getEnumValues() {
                return enumValues;
            }

            public Builder pattern(String pattern) {
                this.pattern = pattern;
                return this;
            }

            public String getPattern() {
                return pattern;
            }

            public Builder minLength(Integer minLength) {
                this.minLength = minLength;
                return this;
            }

            public Integer getMinLength() {
                return minLength;
            }

            public Builder maxLength(Integer maxLength) {
                this.maxLength = maxLength;
                return this;
            }

            public Integer getMaxLength() {
                return maxLength;
            }

            public Builder minimum(BigDecimal minimum) {
                this.minimum = minimum;
                return this;
            }

            public BigDecimal getMinimum() {
                return minimum;
            }

            public Builder maximum(BigDecimal maximum) {
                this.maximum = maximum;
                return this;
            }

            public BigDecimal getMaximum() {
                return maximum;
            }

            public Builder exclusiveMinimum(boolean exclusiveMinimum) {
                this.exclusiveMinimum = exclusiveMinimum;
                return this;
            }

            public Builder exclusiveMaximum(boolean exclusiveMaximum) {
                this.exclusiveMaximum = exclusiveMaximum;
                return this;
            }

            public boolean isExclusiveMinimum() {
                return exclusiveMinimum;
            }

            public boolean isExclusiveMaximum() {
                return exclusiveMaximum;
            }

            public Builder constValue(String constValue) {
                this.constValue = constValue;
                return this;
            }

            public String getConstValue() {
                return constValue;
            }

            public Builder defaultValue(String defaultValue) {
                this.defaultValue = defaultValue;
                return this;
            }

            public String getDefaultValue() {
                return defaultValue;
            }

            public Builder itemsConstraints(SchemaConstraints itemsConstraints) {
                this.itemsConstraints = itemsConstraints;
                return this;
            }

            public Builder allOfConstraints(List<SchemaConstraints> constraints) {
                this.allOfConstraints.clear();
                if (constraints != null) {
                    this.allOfConstraints.addAll(constraints);
                }
                return this;
            }

            public Builder anyOfConstraints(List<SchemaConstraints> constraints) {
                this.anyOfConstraints.clear();
                if (constraints != null) {
                    this.anyOfConstraints.addAll(constraints);
                }
                return this;
            }

            public Builder oneOfConstraints(List<SchemaConstraints> constraints) {
                this.oneOfConstraints.clear();
                if (constraints != null) {
                    this.oneOfConstraints.addAll(constraints);
                }
                return this;
            }

            public void addAllOfConstraint(SchemaConstraints constraints) {
                if (constraints != null) {
                    this.allOfConstraints.add(constraints);
                }
            }

            public void addAnyOfConstraint(SchemaConstraints constraints) {
                if (constraints != null) {
                    this.anyOfConstraints.add(constraints);
                }
            }

            public void addOneOfConstraint(SchemaConstraints constraints) {
                if (constraints != null) {
                    this.oneOfConstraints.add(constraints);
                }
            }

            private void addGuardDetail(String detail) {
                if (detail != null && !detail.isBlank() && !guardDetails.contains(detail)) {
                    guardDetails.add(detail);
                }
            }

            private GuardStrength upgrade(GuardStrength current, GuardStrength candidate) {
                if (current == GuardStrength.NOT_USER_CONTROLLED) {
                    return current;
                }
                if (candidate == null) {
                    return current;
                }
                if (current == null) {
                    return candidate;
                }
                return candidate.ordinal() > current.ordinal() ? candidate : current;
            }

            private String buildRangeDetail() {
                StringBuilder sb = new StringBuilder("range=");
                sb.append(exclusiveMinimum ? "(" : "[");
                sb.append(minimum != null ? minimum.toPlainString() : "-INF");
                sb.append(", ");
                sb.append(maximum != null ? maximum.toPlainString() : "+INF");
                sb.append(exclusiveMaximum ? ")" : "]");
                return sb.toString();
            }

            private void computeGuards() {
                guardDetails.clear();
                GuardStrength strength = GuardStrength.NONE;

                if (readOnly) {
                    strength = GuardStrength.NOT_USER_CONTROLLED;
                    addGuardDetail("readOnly=true");
                } else {
                    if (constValue != null) {
                        strength = upgrade(strength, GuardStrength.STRONG);
                        addGuardDetail("const=" + constValue);
                    }
                    if ("boolean".equals(type)) {
                        strength = upgrade(strength, GuardStrength.STRONG);
                        addGuardDetail("type=boolean");
                    }
                    if (enumValues != null && !enumValues.isEmpty()) {
                        addGuardDetail("enum=" + enumValues);
                        if (enumValues.size() <= 6) {
                            strength = upgrade(strength, GuardStrength.STRONG);
                        } else if (enumValues.size() <= 12) {
                            strength = upgrade(strength, GuardStrength.MODERATE);
                        } else {
                            strength = upgrade(strength, GuardStrength.WEAK);
                        }
                    }
                    if (pattern != null) {
                        strength = upgrade(strength, GuardStrength.MODERATE);
                        addGuardDetail("pattern=" + pattern);
                    }
                    if (maxLength != null) {
                        addGuardDetail("maxLength=" + maxLength);
                        if (maxLength <= 8) {
                            strength = upgrade(strength, GuardStrength.STRONG);
                        } else if (maxLength <= 32) {
                            strength = upgrade(strength, GuardStrength.MODERATE);
                        } else {
                            strength = upgrade(strength, GuardStrength.WEAK);
                        }
                    }
                    if (minLength != null) {
                        strength = upgrade(strength, GuardStrength.WEAK);
                        addGuardDetail("minLength=" + minLength);
                    }
                    if (minimum != null || maximum != null) {
                        addGuardDetail(buildRangeDetail());
                        if (minimum != null && maximum != null) {
                            BigDecimal diff = maximum.subtract(minimum).abs();
                            if (diff.compareTo(BigDecimal.valueOf(10)) <= 0) {
                                strength = upgrade(strength, GuardStrength.STRONG);
                            } else {
                                strength = upgrade(strength, GuardStrength.MODERATE);
                            }
                        } else {
                            strength = upgrade(strength, GuardStrength.WEAK);
                        }
                    }
                    if (defaultValue != null) {
                        addGuardDetail("default=" + defaultValue);
                    }
                    if (optional) {
                        addGuardDetail("optional=true");
                    }
                    if (itemsConstraints != null
                        && itemsConstraints.guardStrength.ordinal() > strength.ordinal()) {
                        strength = itemsConstraints.guardStrength;
                        if (itemsConstraints.guardDetails != null) {
                            for (String detail : itemsConstraints.guardDetails) {
                                addGuardDetail("items." + detail);
                            }
                        }
                    }

                    if (!allOfConstraints.isEmpty()) {
                        for (SchemaConstraints constraint : allOfConstraints) {
                            if (constraint == null) {
                                continue;
                            }
                            strength = upgrade(strength, constraint.guardStrength);
                            if (constraint.guardDetails != null) {
                                for (String detail : constraint.guardDetails) {
                                    addGuardDetail("allOf." + detail);
                                }
                            }
                        }
                    }

                    GuardStrength combinedAny = combineChoiceGuards(anyOfConstraints, "anyOf");
                    strength = adjustForChoice(strength, combinedAny);

                    GuardStrength combinedOne = combineChoiceGuards(oneOfConstraints, "oneOf");
                    strength = adjustForChoice(strength, combinedOne);
                }

                guardStrength = strength;
            }

            private GuardStrength combineChoiceGuards(List<SchemaConstraints> constraints, String label) {
                if (constraints == null || constraints.isEmpty()) {
                    return null;
                }
                boolean allNotUserControlled = true;
                GuardStrength worst = null;
                for (SchemaConstraints constraint : constraints) {
                    if (constraint == null) {
                        continue;
                    }
                    GuardStrength gs = constraint.guardStrength;
                    if (gs != GuardStrength.NOT_USER_CONTROLLED) {
                        allNotUserControlled = false;
                        if (worst == null || gs.ordinal() < worst.ordinal()) {
                            worst = gs;
                        }
                    }
                    if (constraint.guardDetails != null) {
                        for (String detail : constraint.guardDetails) {
                            addGuardDetail(label + "." + detail);
                        }
                    }
                }
                if (allNotUserControlled) {
                    addGuardDetail(label + ".allVariants=readOnly");
                    return GuardStrength.NOT_USER_CONTROLLED;
                }
                if (worst != null) {
                    addGuardDetail(label + ".minGuard=" + worst);
                }
                return worst;
            }

            private GuardStrength adjustForChoice(GuardStrength current, GuardStrength candidate) {
                if (candidate == null) {
                    return current;
                }
                if (current == null || current == GuardStrength.NONE) {
                    return candidate;
                }
                if (current == GuardStrength.NOT_USER_CONTROLLED) {
                    return candidate == GuardStrength.NOT_USER_CONTROLLED ? current : candidate;
                }
                if (candidate == GuardStrength.NOT_USER_CONTROLLED) {
                    return GuardStrength.NOT_USER_CONTROLLED;
                }
                if (current == GuardStrength.NONE) {
                    return candidate;
                }
                return candidate.ordinal() < current.ordinal() ? candidate : candidate.ordinal() > current.ordinal() ? candidate : current;
            }

            public SchemaConstraints build() {
                computeGuards();
                return new SchemaConstraints(this);
            }
        }
    }
}

