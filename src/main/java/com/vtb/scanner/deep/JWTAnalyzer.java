package com.vtb.scanner.deep;

import com.vtb.scanner.heuristics.ConfidenceCalculator;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.semantic.ContextAnalyzer;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.security.SecurityScheme;

import java.util.*;

public class JWTAnalyzer {

    private static final Set<String> GOST_JWT_ALGORITHMS = Set.of("gostr34102012", "gost34102012", "gost");
    private static final Set<String> EXPIRATION_KEYWORDS = Set.of("exp", "expires", "ttl", "lifetime", "expires_in");
    private static final Set<String> ROTATION_KEYWORDS = Set.of("rotate", "rotation", "jti", "token rotation", "refresh token rotation");
    private static final Set<String> ISSUER_KEYWORDS = Set.of("iss", "issuer");
    private static final Set<String> AUDIENCE_KEYWORDS = Set.of("aud", "audience");
    private static final Set<String> BANKING_KEYWORDS = Set.of("psd2", "consent", "aisp", "pisp", "open banking", "consent-id", "psu", "x-psu", "tpp", "x-fapi");
    private static final Set<String> TELECOM_KEYWORDS = Set.of("msisdn", "subscriber", "sim", "telecom", "operator", "roaming", "sbermobile");
    private static final Set<String> TELEMATIC_KEYWORDS = Set.of("vin", "vehicle", "telematics", "connected car", "lada", "ota", "ecu");
    private static final Set<String> ENCRYPTION_KEYWORDS = Set.of("jwe", "encrypted", "encryption", "enc", "aes", "gcm", "crypto", "шифр");

    private JWTAnalyzer() {
    }

    public static List<Vulnerability> analyzeJWT(OpenAPI openAPI,
                                                 ContextAnalyzer.APIContext context) {
        List<Vulnerability> findings = new ArrayList<>();
        if (openAPI == null || openAPI.getComponents() == null ||
            openAPI.getComponents().getSecuritySchemes() == null) {
            return findings;
        }

        boolean highContext = context == ContextAnalyzer.APIContext.BANKING ||
            context == ContextAnalyzer.APIContext.GOVERNMENT ||
            context == ContextAnalyzer.APIContext.HEALTHCARE ||
            context == ContextAnalyzer.APIContext.TELECOM ||
            context == ContextAnalyzer.APIContext.AUTOMOTIVE;

        Map<String, SecurityScheme> securitySchemes = openAPI.getComponents().getSecuritySchemes();
        securitySchemes.forEach((name, scheme) -> {
            if (scheme == null || scheme.getType() != SecurityScheme.Type.HTTP ||
                !"bearer".equalsIgnoreCase(scheme.getScheme())) {
                return;
            }
            String description = Optional.ofNullable(scheme.getDescription()).orElse("");
            String lower = description.toLowerCase(Locale.ROOT);
            boolean bearerIsJwt = scheme.getBearerFormat() == null ||
                scheme.getBearerFormat().toLowerCase(Locale.ROOT).contains("jwt") || lower.contains("jwt");
            if (!bearerIsJwt) {
                return;
            }

            List<JwtIssue> issues = new ArrayList<>();

            boolean telecomContext = mentionsAny(lower, TELECOM_KEYWORDS);
            boolean telematicsContext = mentionsAny(lower, TELEMATIC_KEYWORDS);

            if (!mentionsAny(lower, Set.of("rs256", "es256", "hs256", "ps256", "eddsa", "gost"))) {
                issues.add(new JwtIssue(
                    "MissingAlgorithm",
                    "JWT не описывает алгоритм подписи",
                    "Security scheme '" + name + "' не содержит информации об алгоритме подписи JWT. " +
                        "Без этого невозможно оценить устойчивость к подделке токенов.",
                    "Пропишите используемый алгоритм (RS256/ES256 или ГОСТ Р 34.10-2012). " +
                        "Для symmetric HS256 уточните длину секрета (>256 бит).",
                    Severity.MEDIUM
                ));
            }
            if (lower.contains("\"alg\":\"none\"") || lower.contains("alg=none")) {
                issues.add(new JwtIssue(
                    "NoneAlgorithm",
                    "JWT допускает alg=none (без подписи)",
                    "Описание JWT '" + name + "' содержит указание на алгоритм 'none'. Это позволяет создавать неподписанные токены.",
                    "Запретите 'none'. Настройте библиотеку JWT (disable insecure defaults).",
                    Severity.CRITICAL
                ));
            }
            if (lower.contains("hs256")) {
                issues.add(new JwtIssue(
                    "HS256Warning",
                    "JWT использует HS256 (симметричный секрет)",
                    "HS256 требует сильного секрета и защищенного хранения. " +
                        "В распределённой системе риск утечки секрета растёт.",
                    "Рассмотрите RS256/ES256 или ГОСТ. Если оставляете HS256 — обеспечьте секрет ≥32 байта, rotation и изоляцию.",
                    Severity.MEDIUM
                ));
            }
            boolean hasGOST = GOST_JWT_ALGORITHMS.stream().anyMatch(lower::contains);
            if (!hasGOST && highContext) {
                issues.add(new JwtIssue(
                    "MissingGOST",
                    "JWT не использует ГОСТ подпись",
                    "Для банков/гос систем РФ рекомендована подпись ГОСТ Р 34.10-2012. " +
                        "Схема '" + name + "' не содержит упоминаний ГОСТ.",
                    "Рассмотрите переход на ГОСТ (CryptoPro/BouncyCastle). Либо документируйте, почему ГОСТ не требуется.",
                    Severity.MEDIUM,
                    true
                ));
            }
            if (!mentionsAny(lower, EXPIRATION_KEYWORDS)) {
                issues.add(new JwtIssue(
                    "MissingExpiration",
                    "JWT не описывает срок действия (exp)",
                    "Описание JWT '" + name + "' не содержит упоминаний exp/expires_in. " +
                        "Без лимита времени токен остаётся действительным неопределённо долго.",
                    "Обязательно добавьте claim exp и ограничьте TTL (≤10 мин для access token, ≤1 суток для refresh).",
                    highContext ? Severity.HIGH : Severity.MEDIUM
                ));
            }
            if (!mentionsAny(lower, ROTATION_KEYWORDS)) {
                issues.add(new JwtIssue(
                    "NoRotation",
                    "JWT/refresh token без политики rotation",
                    "Не указаны требования к refresh token rotation (jti, revoke при использовании). Это повышает риск reuse атак.",
                    "Внедрите rotation: каждый refresh token одноразовый, храните jti, при использовании немедленно выпускайте новый.",
                    highContext ? Severity.HIGH : Severity.MEDIUM
                ));
            }
            if (!mentionsAny(lower, ISSUER_KEYWORDS)) {
                issues.add(new JwtIssue(
                    "MissingIssuer",
                    "JWT не описывает issuer (iss)",
                    "Не указано, как проверяется issuer (iss) токена. Это затрудняет проверку подлинности и мульти-tenant сценарии.",
                    "Документируйте значение iss и требование строгого сравнения. При необходимости используйте multiple issuers с валидацией.",
                    Severity.MEDIUM
                ));
            }
            if (!mentionsAny(lower, AUDIENCE_KEYWORDS)) {
                issues.add(new JwtIssue(
                    "MissingAudience",
                    "JWT не описывает audience (aud)",
                    "Нет упоминаний audience (aud). Без aud токены могут быть переиспользованы на других сервисах.",
                    "Используйте aud для ограничения области действия токена (например, aud=payments-api).",
                    Severity.MEDIUM
                ));
            }
            if (context == ContextAnalyzer.APIContext.BANKING && !mentionsAny(lower, BANKING_KEYWORDS)) {
                issues.add(new JwtIssue(
                    "NoBankingContext",
                    "JWT не учитывает банковские требования",
                    "Описание JWT не содержит PSD2/OpenBanking требований (consent-id, PSU, TPP идентификаторы).",
                    "Добавьте информацию о consent-id, PSU-IP-Address, TPP-roles. Убедитесь, что JWT содержит необходимые claims.",
                    Severity.HIGH
                ));
            }
            if (!mentionsAny(lower, Set.of("kid", "key id", "jwks", "rotation"))) {
                issues.add(new JwtIssue(
                    "NoKeyRotation",
                    "Нет описания key rotation (kid/JWKS)",
                    "Не упомянута выдача kid и JWKS endpoint. Без rotation ключей повышается риск компрометации подписи.",
                    "Опубликуйте JWKS endpoint, добавьте kid в заголовок JWT, регламентируйте периодическую замену ключей.",
                    highContext ? Severity.HIGH : Severity.MEDIUM
                ));
            }
            if ((telecomContext || telematicsContext) && !mentionsAny(lower, ENCRYPTION_KEYWORDS)) {
                issues.add(new JwtIssue(
                    "NoTokenEncryption",
                    "JWT для телеком/телеематики без шифрования",
                    "Описание JWT '" + name + "' относится к телеком/connected-car сценариям (MSISDN/VIN), но не содержит требований по шифрованию/ЖWE.",
                    "Для защиты чувствительных данных используйте JWE или защищённый канал доставки (encrypt-at-rest, AES-GCM). " +
                        "Документируйте ключи, алгоритмы и контроль доступа.",
                    Severity.HIGH
                ));
            }

            for (JwtIssue issue : issues) {
                findings.add(buildSchemeFinding(name, issue));
            }
        });

        analyzeTokenSchemas(openAPI, context, findings);
        return findings;
    }

    private static void analyzeTokenSchemas(OpenAPI openAPI,
                                            ContextAnalyzer.APIContext context,
                                            List<Vulnerability> findings) {
        if (openAPI.getComponents() == null || openAPI.getComponents().getSchemas() == null) {
            return;
        }
        Map<String, Schema<?>> schemas = castSchemaMap(openAPI.getComponents().getSchemas());
        boolean highContext = context == ContextAnalyzer.APIContext.BANKING ||
            context == ContextAnalyzer.APIContext.GOVERNMENT ||
            context == ContextAnalyzer.APIContext.HEALTHCARE ||
            context == ContextAnalyzer.APIContext.TELECOM ||
            context == ContextAnalyzer.APIContext.AUTOMOTIVE;

        schemas.forEach((name, schema) -> {
            if (schema == null || schema.getProperties() == null) {
                return;
            }
            String lowerName = name.toLowerCase(Locale.ROOT);
            if (!(lowerName.contains("token") || lowerName.contains("jwt") || lowerName.contains("oauth") || lowerName.contains("auth"))) {
                return;
            }
            Map<String, Schema<?>> properties = castSchemaMap(schema.getProperties());
            Set<String> propNames = new HashSet<>();
            properties.keySet().forEach(prop -> propNames.add(prop.toLowerCase(Locale.ROOT)));

            if (propNames.stream().noneMatch(prop -> prop.contains("expire") || prop.contains("ttl"))) {
                findings.add(buildSchemaFinding(
                    name,
                    "Token response без срока действия",
                    "Схема '" + name + "' не содержит поля expires_in/expires_at. Клиенты не узнают когда протухает токен.",
                    highContext ? Severity.HIGH : Severity.MEDIUM,
                    "Добавьте expires_in (в секундах) или expires_at. Это обязательное поле в OAuth/OpenID Connect."
                ));
            }
            boolean hasRefresh = propNames.stream().anyMatch(prop -> prop.contains("refresh"));
            if (!hasRefresh && (propNames.contains("access_token") || propNames.contains("token"))) {
                findings.add(buildSchemaFinding(
                    name,
                    "Token response без refresh_token",
                    "Схема '" + name + "' возвращает access_token, но отсутствует refresh_token. " +
                        "Без refresh приходится хранить долго живущие access токены.",
                    highContext ? Severity.MEDIUM : Severity.LOW,
                    "Добавьте refresh_token или документируйте причину отсутствия. " +
                        "Рекомендуется короткий срок для access token + refresh rotation."
                ));
            }
            if (!propNames.contains("scope")) {
                findings.add(buildSchemaFinding(
                    name,
                    "Token response без scope",
                    "Схема '" + name + "' не содержит поля scope. Клиент не узнает какие права выданы токену.",
                    Severity.MEDIUM,
                    "Включите scope в ответ token endpoint (строка с пробелами между scopes)."
                ));
            }
            if (!propNames.contains("token_type")) {
                findings.add(buildSchemaFinding(
                    name,
                    "Token response без token_type",
                    "В ответе '" + name + "' отсутствует token_type (обычно Bearer). Это обязательное поле RFC 6749.",
                    Severity.LOW,
                    "Добавьте token_type: Bearer."
                ));
            }
        });
    }

    private static Map<String, Schema<?>> castSchemaMap(Map<?, ?> source) {
        if (source == null || source.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, Schema<?>> result = new LinkedHashMap<>();
        source.forEach((key, value) -> {
            if (key instanceof String strKey && value instanceof Schema<?> schema) {
                result.put(strKey, schema);
            }
        });
        return result;
    }

    private static boolean mentionsAny(String textLower, Set<String> keywords) {
        for (String keyword : keywords) {
            if (textLower.contains(keyword.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static Vulnerability buildSchemeFinding(String schemeName, JwtIssue issue) {
        VulnerabilityType type = issue.gostRelated ? VulnerabilityType.GOST_VIOLATION : VulnerabilityType.BROKEN_AUTHENTICATION;
        Vulnerability temp = Vulnerability.builder()
            .type(type)
            .severity(issue.severity)
            .build();
        return Vulnerability.builder()
            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                type, "components/securitySchemes/" + schemeName, "N/A", schemeName, issue.type))
            .type(type)
            .severity(issue.severity)
            .title(issue.title)
            .description(issue.description)
            .endpoint("components/securitySchemes/" + schemeName)
            .method("N/A")
            .recommendation(issue.recommendation)
            .owaspCategory("API2:2023 - Broken Authentication")
            .evidence("Scheme: " + schemeName)
            .confidence(ConfidenceCalculator.calculateConfidence(temp, null, false, true))
            .priority(ConfidenceCalculator.calculatePriority(temp,
                ConfidenceCalculator.calculateConfidence(temp, null, false, true)))
            .gostRelated(issue.gostRelated)
            .build();
    }

    private static Vulnerability buildSchemaFinding(String schemaName,
                                                    String title,
                                                    String description,
                                                    Severity severity,
                                                    String recommendation) {
        Vulnerability temp = Vulnerability.builder()
            .type(VulnerabilityType.BROKEN_AUTHENTICATION)
            .severity(severity)
            .build();
        return Vulnerability.builder()
            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                VulnerabilityType.BROKEN_AUTHENTICATION, "components/schemas/" + schemaName, "N/A", schemaName, title))
            .type(VulnerabilityType.BROKEN_AUTHENTICATION)
            .severity(severity)
            .title(title)
            .description(description)
            .endpoint("components/schemas/" + schemaName)
            .method("N/A")
            .recommendation(recommendation)
            .owaspCategory("API2:2023 - Broken Authentication")
            .evidence("Schema: " + schemaName)
            .confidence(ConfidenceCalculator.calculateConfidence(temp, null, false, true))
            .priority(ConfidenceCalculator.calculatePriority(temp,
                ConfidenceCalculator.calculateConfidence(temp, null, false, true)))
            .build();
    }

    private static class JwtIssue {
        final String type;
        final String title;
        final String description;
        final String recommendation;
        final Severity severity;
        final boolean gostRelated;

        JwtIssue(String type,
                 String title,
                 String description,
                 String recommendation,
                 Severity severity) {
            this(type, title, description, recommendation, severity, false);
        }

        JwtIssue(String type,
                 String title,
                 String description,
                 String recommendation,
                 Severity severity,
                 boolean gostRelated) {
            this.type = type;
            this.title = title;
            this.description = description;
            this.recommendation = recommendation;
            this.severity = severity;
            this.gostRelated = gostRelated;
        }
    }
}

