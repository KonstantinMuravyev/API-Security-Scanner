package com.vtb.scanner.util;

import com.vtb.scanner.config.ScannerConfig;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Утилитные эвристики для распознавания механизмов доступа в OpenAPI операциях.
 * Нужны, чтобы различать реальные проблемы и бизнес-требования (consent/token based access).
 */
public final class AccessControlHeuristics {

    private static final Set<String> ACCESS_TEXT_MARKERS = new LinkedHashSet<>(Arrays.asList(
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
        "permissions",
        "2fa",
        "mfa",
        "otp",
        "fapi",
        "esia",
        "esiatoken",
        "esid",
        "smev",
        "gosuslugi",
        "sbbol",
        "sberid",
        "sber id",
        "sbp",
        "mirpay",
        "mir pay",
        "fast payment",
        "fps",
        "miraccept",
        "psu",
        "tpp",
        "qualified signature",
        "digital signature",
        "kval",
        "cryptopro",
        "trusted device",
        "device binding",
        "mir",
        "3ds",
        "visa secure",
        "sbermobile",
        "msisdn",
        "vin",
        "lada connect",
        "remote start",
        "vehicle telemetry"
    ));

    private static final Set<String> HEADER_NAMES = new LinkedHashSet<>(Arrays.asList(
        "x-consent-id",
        "x-requesting-bank",
        "x-payment-consent-id",
        "x-product-agreement-consent-id",
        "x-fapi-interaction-id",
        "x-fapi-customer-ip-address",
        "x-fapi-user-agent",
        "x-fapi-authorization",
        "x-esia-token",
        "x-esia-auth",
        "x-sbbol-session",
        "x-smev-signature",
        "x-rgns-token",
        "x-gosuslugi-ticket",
        "x-device-id",
        "x-request-id",
        "x-psu-id",
        "x-psu-ip-address",
        "x-psu-corporate-id",
        "x-tpp-signature-certificate",
        "x-mir-accept",
        "x-3ds-token",
        "x-msisdn",
        "x-subscriber-id",
        "x-sim-id",
        "x-device-serial",
        "x-vin",
        "x-lada-session"
    ));

    private static final Set<String> OPEN_BANKING_HEADERS = new LinkedHashSet<>(List.of(
        "authorization"
    ));

    private static final Set<String> QUERY_NAMES = new LinkedHashSet<>(Arrays.asList(
        "client_id",
        "consent_id",
        "requesting_bank",
        "payment_consent_id",
        "product_agreement_consent_id",
        "bank_code",
        "esia_token",
        "esid",
        "smev_request_id",
        "sbbol_session",
        "gosuslugi_ticket",
        "psu_id",
        "psu_ip",
        "tpp_id",
        "device_id",
        "request_id",
        "msisdn",
        "vin",
        "vehicle_id",
        "lada_session",
        "sbp_request_id",
        "sbp_payment_id",
        "sbp_member_id",
        "mir_pay_session",
        "mir_pay_device"
    ));

    private static final Set<String> BODY_PROPERTY_NAMES = new LinkedHashSet<>(Arrays.asList(
        "client_id",
        "consent_id",
        "permissions",
        "requesting_bank",
        "allowed_creditor_accounts",
        "allowed_product_types",
        "max_amount",
        "esia_token",
        "esid",
        "sbbol_session",
        "smev_request_id",
        "psu_id",
        "psu_ip",
        "device_id",
        "tpp_id",
        "trusted_device_id",
        "digital_signature",
        "msisdn",
        "subscriber_id",
        "vin",
        "vehicle_id",
        "device_serial",
        "telematics",
        "sbp_request_id",
        "sbp_payment_id",
        "sbp_member_id",
        "mir_pay_session",
        "mir_pay_device",
        "qr_token"
    ));

    private static final Set<String> CONSENT_MARKERS = new LinkedHashSet<>(Arrays.asList(
        "consent",
        "x-consent-id",
        "permissions",
        "allowed_product_types",
        "allowed_creditor_accounts",
        "payment_consent",
        "product_agreement_consent",
        "esia",
        "esid",
        "sbbol",
        "sberid",
        "mir pay",
        "smev",
        "gosuslugi",
        "tpp",
        "qualified signature",
        "digital signature",
        "miraccept",
        "3ds",
        "msisdn",
        "sbermobile",
        "trusted device",
        "vin",
        "connected car"
    ));

    private static final Set<String> OPEN_BANKING_PATH_MARKERS = new LinkedHashSet<>(Arrays.asList(
        "open-banking",
        "openbank",
        "psd2",
        "account-access-consents",
        "funds-confirmation",
        "domestic-payments",
        "international-payments",
        "payments",
        "accounts",
        "consents",
        "tpp",
        "psu",
        "x-fapi",
        "sbp",
        "fast-pay",
        "mir-pay"
    ));

    private static final Set<String> OPEN_BANKING_TEXT_MARKERS = new LinkedHashSet<>(Arrays.asList(
        "open banking",
        "psd2",
        "psu",
        "tpp",
        "consent",
        "permissions",
        "funds confirmation",
        "domestic payment",
        "international payment",
        "payment initiation",
        "account information",
        "account access",
        "fapi",
        "ob api",
        "obapi",
        "sbp",
        "fast payment system",
        "mir pay",
        "sber id"
    ));

    private static final Set<String> STRONG_AUTH_TEXT_MARKERS = new LinkedHashSet<>(Arrays.asList(
        "bearer token",
        "authorization header",
        "oauth2",
        "oauth 2.0",
        "jwt",
        "signed jwt",
        "psd2 token",
        "mutual tls",
        "mtls",
        "m-tls",
        "tls client cert",
        "dpop",
        "jws",
        "jwk",
        "signed request",
        "client assertion",
        "tpp certificate",
        "miraccept",
        "mir pay",
        "sberid",
        "gosuslugi"
    ));

    private static final Set<String> STRONG_AUTH_HEADER_NAMES = new LinkedHashSet<>(Arrays.asList(
        "authorization",
        "proxy-authorization",
        "x-authorization",
        "x-psu-authorization",
        "x-tpp-authorization",
        "x-fapi-authorization",
        "dpop",
        "x-dpop",
        "x-jws-signature"
    ));

    static {
        applyConfigOverrides();
    }

    private static void applyConfigOverrides() {
        try {
            ScannerConfig config = ScannerConfig.load();
            if (config == null || config.getAccessControl() == null) {
                return;
            }
            ScannerConfig.AccessControl access = config.getAccessControl();
            addAllLowercase(ACCESS_TEXT_MARKERS, access.getAccessTextMarkers());
            addAllLowercase(HEADER_NAMES, access.getHeaderNames());
            addAllLowercase(QUERY_NAMES, access.getQueryNames());
            addAllLowercase(BODY_PROPERTY_NAMES, access.getBodyPropertyNames());
            addAllLowercase(CONSENT_MARKERS, access.getConsentMarkers());
            addAllLowercase(OPEN_BANKING_PATH_MARKERS, access.getOpenBankingPathMarkers());
            addAllLowercase(OPEN_BANKING_TEXT_MARKERS, access.getOpenBankingTextMarkers());
            addAllLowercase(STRONG_AUTH_TEXT_MARKERS, access.getStrongAuthTextMarkers());
            addAllLowercase(STRONG_AUTH_HEADER_NAMES, access.getStrongAuthHeaderNames());
        } catch (Exception e) {
            System.err.println("AccessControlHeuristics: не удалось применить overrides из конфигурации: " + e.getMessage());
        }
    }

    private static void addAllLowercase(Set<String> target, List<String> values) {
        if (target == null || values == null) {
            return;
        }
        for (String value : values) {
            if (value == null) {
                continue;
            }
            String normalized = value.trim().toLowerCase(Locale.ROOT);
            if (!normalized.isEmpty()) {
                target.add(normalized);
            }
        }
    }

    private static boolean containsAny(String text, Set<String> markers) {
        if (text == null || text.isEmpty() || markers == null || markers.isEmpty()) {
            return false;
        }
        for (String marker : markers) {
            if (marker != null && !marker.isEmpty() && text.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    private AccessControlHeuristics() {
        // utility
    }

    private static final int MAX_DEPTH = 12;

    /**
     * Пытается определить, описана ли в спецификации какая-либо защита доступа:
     * наличие consent заголовков, токенов, OAuth scope и т.п.
     */
    public static boolean hasExplicitAccessControl(Operation operation, String path) {
        return hasExplicitAccessControl(operation, path, null);
    }

    /**
     * Расширенная версия с доступом к OpenAPI для разрешения $ref.
     */
    public static boolean hasExplicitAccessControl(Operation operation, String path, OpenAPI openAPI) {
        if (operation == null) {
            return false;
        }

        // 1. OAuth scope в security requirements
        if (hasSecurityScopes(operation, openAPI)) {
            return true;
        }

        boolean consentHeaders = hasConsentHeaders(operation);
        boolean consentBody = hasConsentFieldsInBody(operation, openAPI);

        // 2. Текст описания / summary
        StringBuilder textBuilder = new StringBuilder();
        if (operation.getSummary() != null) {
            textBuilder.append(operation.getSummary()).append(' ');
        }
        if (operation.getDescription() != null) {
            textBuilder.append(operation.getDescription());
        }
        String text = textBuilder.toString().toLowerCase(Locale.ROOT);
        boolean tokenMentioned = containsAny(text, ACCESS_TEXT_MARKERS);

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

        boolean hasSecurityDefinition = hasAnySecurity(operation, openAPI);

        if (tokenMentioned && hasSecurityDefinition) {
            return true;
        }

        return hasStrongAuthorization(operation, openAPI);
    }

    public static boolean hasSecurityScopes(Operation operation) {
        return hasSecurityScopes(operation, null);
    }

    public static boolean hasSecurityScopes(Operation operation, OpenAPI openAPI) {
        if (operation == null || operation.getSecurity() == null) {
            return false;
        }
        for (SecurityRequirement requirement : operation.getSecurity()) {
            for (Map.Entry<String, List<String>> entry : requirement.entrySet()) {
                List<String> scopes = entry.getValue();
                if (scopes != null && !scopes.isEmpty()) {
                    return true;
                }
                if (isStrongScheme(openAPI, entry.getKey())) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean hasConsentEvidence(Operation operation) {
        return hasConsentEvidence(operation, null);
    }

    public static boolean hasConsentEvidence(Operation operation, OpenAPI openAPI) {
        return hasConsentHeaders(operation) || hasConsentFieldsInBody(operation, openAPI);
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

    private static boolean hasConsentFieldsInBody(Operation operation, OpenAPI openAPI) {
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
            if (schemaContainsAnyProperty(mediaType.getSchema(), BODY_PROPERTY_NAMES, new HashSet<>(), openAPI, 0)) {
                return true;
            }
        }
        return false;
    }

    @SuppressWarnings("rawtypes")
    private static boolean schemaContainsAnyProperty(Schema<?> schema,
                                                     Set<String> propertyNames,
                                                     Set<Schema<?>> visited,
                                                     OpenAPI openAPI,
                                                     int depth) {
        if (schema == null || propertyNames.isEmpty()) {
            return false;
        }
        if (depth > MAX_DEPTH) {
            return false;
        }
        if (!visited.add(schema)) {
            return false;
        }

        Schema<?> effectiveSchema = resolveRef(schema, openAPI, depth);
        if (effectiveSchema != schema) {
            schema = effectiveSchema;
            if (!visited.add(schema)) {
                return false;
            }
        }

        Map<String, Schema> properties = schema.getProperties();
        if (properties != null) {
            for (Map.Entry<String, Schema> entry : properties.entrySet()) {
                String key = entry.getKey();
                if (key != null && propertyNames.contains(key.toLowerCase(Locale.ROOT))) {
                    return true;
                }
                Schema<?> nested = entry.getValue();
                if (schemaContainsAnyProperty(nested, propertyNames, visited, openAPI, depth + 1)) {
                    return true;
                }
            }
        }

        Schema<?> items = schema.getItems();
        if (items != null && schemaContainsAnyProperty(items, propertyNames, visited, openAPI, depth + 1)) {
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
        return containsAny(text, CONSENT_MARKERS);
    }

    private static Schema<?> resolveRef(Schema<?> schema, OpenAPI openAPI, int depth) {
        if (schema == null) {
            return null;
        }
        String ref = schema.get$ref();
        if (ref == null || openAPI == null || openAPI.getComponents() == null) {
            return schema;
        }
        if (!ref.contains("/components/schemas/")) {
            return schema;
        }
        String name = ref.substring(ref.lastIndexOf('/') + 1);
        Schema<?> resolved = openAPI.getComponents().getSchemas() != null
            ? openAPI.getComponents().getSchemas().get(name)
            : null;
        if (resolved == null || resolved == schema) {
            return schema;
        }
        if (depth + 1 > MAX_DEPTH) {
            return schema;
        }
        return resolved;
    }

    private static boolean hasAnySecurity(Operation operation, OpenAPI openAPI) {
        if (operation != null && operation.getSecurity() != null && !operation.getSecurity().isEmpty()) {
            return true;
        }
        if (openAPI == null) {
            return false;
        }
        if (openAPI.getSecurity() != null && !openAPI.getSecurity().isEmpty()) {
            return true;
        }
        if (openAPI.getComponents() != null && openAPI.getComponents().getSecuritySchemes() != null) {
            Map<String, SecurityScheme> schemes = openAPI.getComponents().getSecuritySchemes();
            return schemes != null && !schemes.isEmpty();
        }
        return false;
    }

    public static boolean hasStrongAuthorization(Operation operation, OpenAPI openAPI) {
        if (operation != null && operation.getSecurity() != null) {
            for (SecurityRequirement requirement : operation.getSecurity()) {
                for (String schemeName : requirement.keySet()) {
                    if (isStrongScheme(openAPI, schemeName)) {
                        return true;
                    }
                }
            }
        }

        if (operation != null && operation.getParameters() != null) {
            for (Parameter parameter : operation.getParameters()) {
                if (parameter == null || parameter.getName() == null) {
                    continue;
                }
                String name = parameter.getName().toLowerCase(Locale.ROOT);
                String canonical = name.replaceAll("[^a-z0-9]", "");
                if (STRONG_AUTH_HEADER_NAMES.contains(name) || STRONG_AUTH_HEADER_NAMES.contains(canonical) || OPEN_BANKING_HEADERS.contains(name)) {
                    String description = parameter.getDescription() != null
                        ? parameter.getDescription().toLowerCase(Locale.ROOT)
                        : "";
                    if (containsAny(description, STRONG_AUTH_TEXT_MARKERS) || description.contains("token")) {
                        return true;
                    }
                }
            }
        }

        if (operation != null) {
            StringBuilder builder = new StringBuilder();
            if (operation.getSummary() != null) {
                builder.append(operation.getSummary()).append(' ');
            }
            if (operation.getDescription() != null) {
                builder.append(operation.getDescription());
            }
            String text = builder.toString().toLowerCase(Locale.ROOT);
            if (containsAny(text, STRONG_AUTH_TEXT_MARKERS)) {
                return true;
            }
        }

        if (openAPI != null && openAPI.getSecurity() != null) {
            for (SecurityRequirement requirement : openAPI.getSecurity()) {
                for (String schemeName : requirement.keySet()) {
                    if (isStrongScheme(openAPI, schemeName)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    public static boolean hasStrongAuthorization(OpenAPI openAPI, String schemeName) {
        return isStrongScheme(openAPI, schemeName);
    }

    public static boolean isOpenBankingOperation(String path, Operation operation, OpenAPI openAPI) {
        String lowerPath = path != null ? path.toLowerCase(Locale.ROOT) : "";
        if (containsAny(lowerPath, OPEN_BANKING_PATH_MARKERS)) {
            return true;
        }

        StringBuilder builder = new StringBuilder();
        if (operation != null) {
            if (operation.getSummary() != null) {
                builder.append(operation.getSummary()).append(' ');
            }
            if (operation.getDescription() != null) {
                builder.append(operation.getDescription());
            }
        }
        String text = builder.toString().toLowerCase(Locale.ROOT);
        if (containsAny(text, OPEN_BANKING_TEXT_MARKERS)) {
            return true;
        }

        if (operation != null && operation.getParameters() != null) {
            for (Parameter parameter : operation.getParameters()) {
                if (parameter == null || parameter.getName() == null) {
                    continue;
                }
                String name = parameter.getName().toLowerCase(Locale.ROOT);
                if (HEADER_NAMES.contains(name) || OPEN_BANKING_HEADERS.contains(name) || QUERY_NAMES.contains(name)) {
                    return true;
                }
            }
        }

        if (openAPI != null) {
            if (openAPI.getServers() != null) {
                for (Server server : openAPI.getServers()) {
                    if (server != null && server.getUrl() != null) {
                        String url = server.getUrl().toLowerCase(Locale.ROOT);
                        if (containsAny(url, OPEN_BANKING_PATH_MARKERS)) {
                            return true;
                        }
                    }
                }
            }
            if (openAPI.getComponents() != null && openAPI.getComponents().getSecuritySchemes() != null) {
                for (Map.Entry<String, SecurityScheme> entry : openAPI.getComponents().getSecuritySchemes().entrySet()) {
                    if (entry.getKey() != null && containsAny(entry.getKey().toLowerCase(Locale.ROOT), OPEN_BANKING_TEXT_MARKERS)) {
                        return true;
                    }
                    SecurityScheme scheme = entry.getValue();
                    if (scheme != null && scheme.getDescription() != null) {
                        String schemeDescription = scheme.getDescription().toLowerCase(Locale.ROOT);
                        if (containsAny(schemeDescription, OPEN_BANKING_TEXT_MARKERS)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    private static boolean isStrongScheme(OpenAPI openAPI, String schemeName) {
        if (schemeName == null || openAPI == null || openAPI.getComponents() == null ||
            openAPI.getComponents().getSecuritySchemes() == null) {
            return false;
        }
        SecurityScheme scheme = openAPI.getComponents().getSecuritySchemes().get(schemeName);
        if (scheme == null) {
            return false;
        }
        SecurityScheme.Type type = scheme.getType();
        if (type == null) {
            return false;
        }
        if (type == SecurityScheme.Type.OAUTH2 || type == SecurityScheme.Type.OPENIDCONNECT) {
            return true;
        }
        if (type == SecurityScheme.Type.MUTUALTLS) {
            return true;
        }
        if (type == SecurityScheme.Type.HTTP && scheme.getScheme() != null) {
            String httpScheme = scheme.getScheme().toLowerCase(Locale.ROOT);
            if ("bearer".equals(httpScheme) || "digest".equals(httpScheme)) {
                return true;
            }
            if (containsAny(httpScheme, STRONG_AUTH_TEXT_MARKERS)) {
                return true;
            }
        }
        if (scheme.getDescription() != null && containsAny(scheme.getDescription().toLowerCase(Locale.ROOT), STRONG_AUTH_TEXT_MARKERS)) {
            return true;
        }
        if (type == SecurityScheme.Type.APIKEY && scheme.getIn() == SecurityScheme.In.HEADER &&
            scheme.getName() != null && scheme.getName().equalsIgnoreCase("authorization")) {
            return true;
        }
        return false;
    }
}

