package com.vtb.scanner.util;

import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.security.SecurityRequirement;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Утилитные эвристики для распознавания механизмов доступа в OpenAPI операциях.
 * Нужны, чтобы различать реальные проблемы и бизнес-требования (consent/token based access).
 */
public final class AccessControlHeuristics {

    private static final Set<String> ACCESS_TEXT_MARKERS = Set.of(
        "client_token",
        "bank_token",
        "access token",
        "bearer",
        "oauth",
        "consent",
        "x-consent-id",
        "x-requesting-bank",
        "scp.",
        "scope",
        "permission",
        "permissions", // консенсус openbanking
        "2fa",
        "mfa",
        "otp",
        "fapi"
    );

    private static final Set<String> HEADER_NAMES = Set.of(
        "x-consent-id",
        "x-requesting-bank",
        "x-payment-consent-id",
        "x-product-agreement-consent-id",
        "x-fapi-interaction-id",
        "x-fapi-customer-ip-address",
        "x-fapi-user-agent",
        "x-fapi-authorization"
    );

    private static final Set<String> QUERY_NAMES = Set.of(
        "client_id",
        "consent_id",
        "requesting_bank",
        "payment_consent_id",
        "product_agreement_consent_id",
        "bank_code"
    );

    private static final Set<String> BODY_PROPERTY_NAMES = Set.of(
        "client_id",
        "consent_id",
        "permissions",
        "requesting_bank",
        "allowed_creditor_accounts",
        "allowed_product_types",
        "max_amount"
    );

    private static final Set<String> CONSENT_MARKERS = Set.of(
        "consent",
        "x-consent-id",
        "permissions",
        "allowed_product_types",
        "allowed_creditor_accounts",
        "payment_consent",
        "product_agreement_consent"
    );

    private AccessControlHeuristics() {
        // utility
    }

    /**
     * Пытается определить, описана ли в спецификации какая-либо защита доступа:
     * наличие consent заголовков, токенов, OAuth scope и т.п.
     */
    public static boolean hasExplicitAccessControl(Operation operation, String path) {
        if (operation == null) {
            return false;
        }

        // 1. OAuth scope в security requirements
        if (hasSecurityScopes(operation)) {
            return true;
        }

        boolean consentHeaders = hasConsentHeaders(operation);
        boolean consentBody = hasConsentFieldsInBody(operation);

        // 2. Текст описания / summary
        StringBuilder textBuilder = new StringBuilder();
        if (operation.getSummary() != null) {
            textBuilder.append(operation.getSummary()).append(' ');
        }
        if (operation.getDescription() != null) {
            textBuilder.append(operation.getDescription());
        }
        String text = textBuilder.toString().toLowerCase(Locale.ROOT);
        boolean tokenMentioned = ACCESS_TEXT_MARKERS.stream().anyMatch(text::contains);

        // 3. Параметры (headers/query)
        if (operation.getParameters() != null) {
            for (Parameter parameter : operation.getParameters()) {
                if (parameter == null || parameter.getName() == null) {
                    continue;
                }
                String name = parameter.getName().toLowerCase(Locale.ROOT);
                if (HEADER_NAMES.contains(name) || QUERY_NAMES.contains(name)) {
                    consentHeaders = true;
                }
            }
        }

        if (consentHeaders || consentBody) {
            return true;
        }

        return tokenMentioned && hasSecurityScopes(operation);
    }

    public static boolean hasSecurityScopes(Operation operation) {
        if (operation == null || operation.getSecurity() == null) {
            return false;
        }
        for (SecurityRequirement requirement : operation.getSecurity()) {
            for (List<String> scopes : requirement.values()) {
                if (scopes != null && !scopes.isEmpty()) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean hasConsentEvidence(Operation operation) {
        return hasConsentHeaders(operation) || hasConsentFieldsInBody(operation);
    }

    private static boolean hasConsentHeaders(Operation operation) {
        if (operation == null || operation.getParameters() == null) {
            return false;
        }
        for (Parameter parameter : operation.getParameters()) {
            if (parameter == null || parameter.getName() == null) {
                continue;
            }
            String name = parameter.getName().toLowerCase(Locale.ROOT);
            String canonical = name.replaceAll("[^a-z0-9]", "");
            if (HEADER_NAMES.contains(name) || HEADER_NAMES.contains(canonical) ||
                QUERY_NAMES.contains(name) || QUERY_NAMES.contains(canonical)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasConsentFieldsInBody(Operation operation) {
        if (operation == null || operation.getRequestBody() == null) {
            return false;
        }
        Content content = operation.getRequestBody().getContent();
        if (content == null) {
            return false;
        }
        for (MediaType mediaType : content.values()) {
            if (mediaType == null || mediaType.getSchema() == null) {
                continue;
            }
            if (schemaContainsAnyProperty(mediaType.getSchema(), BODY_PROPERTY_NAMES, new HashSet<>())) {
                return true;
            }
        }
        return false;
    }

    private static boolean schemaContainsAnyProperty(Schema<?> schema,
                                                     Set<String> propertyNames,
                                                     Set<Schema<?>> visited) {
        if (schema == null || propertyNames.isEmpty()) {
            return false;
        }
        if (!visited.add(schema)) {
            return false;
        }

        if (schema.getProperties() != null) {
            @SuppressWarnings("rawtypes")
            Map properties = schema.getProperties();
            @SuppressWarnings("unchecked")
            Set<Map.Entry<String, Schema>> entries = properties.entrySet();
            for (Map.Entry<String, Schema> entry : entries) {
                String key = entry.getKey();
                if (key != null && propertyNames.contains(key.toLowerCase(Locale.ROOT))) {
                    return true;
                }
                Schema<?> nested = entry.getValue();
                if (schemaContainsAnyProperty(nested, propertyNames, visited)) {
                    return true;
                }
            }
        }

        Schema<?> items = schema.getItems();
        if (items != null && schemaContainsAnyProperty(items, propertyNames, visited)) {
            return true;
        }

        return false;
    }

    public static boolean mentionsPersonalData(Operation operation) {
        if (operation == null) {
            return false;
        }
        StringBuilder textBuilder = new StringBuilder();
        if (operation.getSummary() != null) textBuilder.append(operation.getSummary()).append(' ');
        if (operation.getDescription() != null) textBuilder.append(operation.getDescription()).append(' ');
        String text = textBuilder.toString().toLowerCase(Locale.ROOT);
        return CONSENT_MARKERS.stream().anyMatch(text::contains);
    }
}

