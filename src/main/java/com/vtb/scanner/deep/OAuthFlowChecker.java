package com.vtb.scanner.deep;

import com.vtb.scanner.heuristics.ConfidenceCalculator;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.semantic.ContextAnalyzer;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

@Slf4j
public class OAuthFlowChecker {

    private static final Set<String> WILDCARD_SCOPES = Set.of("*", "all", "full", "admin", "root", "superuser");
    private static final Set<String> BANKING_REQUIRED_SCOPES = Set.of("accounts", "payments", "funds", "consents", "aisp", "pisp");
    private static final Set<String> PKCE_EXTENSION_KEYS = Set.of(
        "x-pkce-required", "x-oauth-pkce-required", "x-requires-pkce", "x-ibm-pkce-required"
    );
    private static final Set<String> STATE_KEYWORDS = Set.of("state", "anti-csrf", "csrf", "anti forgery", "anti-forgery");
    private static final Set<String> NONCE_KEYWORDS = Set.of("nonce", "id_token nonce", "replay protection");
    private static final Set<String> OPENID_KEYWORDS = Set.of("openid", "oidc", "id token");
    private static final Set<String> MTLS_KEYWORDS = Set.of("mtls", "mutual tls", "mutual-tls", "client certificate", "tls client auth", "mutual tls authentication");
    private static final Set<String> PRIVATE_KEY_JWT_KEYWORDS = Set.of("private_key_jwt", "client assertion", "signed jwt", "jwt bearer", "ps256", "rs256 client", "client-jwt");

    private OAuthFlowChecker() {
    }

    public static List<Vulnerability> checkOAuthFlows(OpenAPI openAPI,
                                                      ContextAnalyzer.APIContext context) {
        log.info("Проверка OAuth flows (context={})", context);
        List<Vulnerability> findings = new ArrayList<>();
        if (openAPI == null || openAPI.getComponents() == null ||
            openAPI.getComponents().getSecuritySchemes() == null) {
            return findings;
        }

        boolean isHighContext = context == ContextAnalyzer.APIContext.BANKING ||
            context == ContextAnalyzer.APIContext.GOVERNMENT ||
            context == ContextAnalyzer.APIContext.HEALTHCARE ||
            context == ContextAnalyzer.APIContext.TELECOM ||
            context == ContextAnalyzer.APIContext.AUTOMOTIVE;

        openAPI.getComponents().getSecuritySchemes().forEach((name, scheme) -> {
            if (scheme == null || scheme.getType() != SecurityScheme.Type.OAUTH2) {
                return;
            }
            OAuthFlows flows = scheme.getFlows();
            if (flows == null) {
                findings.add(buildVulnerability(
                    name,
                    "OAuth схема без flows",
                "OAuth2 схема '" + name + "' не описывает допустимые grant types. Это препятствует валидации безопасности.",
                    highSeverity(isHighContext),
                    "Опишите authorizationCode/clientCredentials/refreshToken/… потоки в components.securitySchemes." +
                        "\nДобавьте scopes и URLs."
                ));
                return;
            }

            String description = Optional.ofNullable(scheme.getDescription()).orElse("");
            Map<String, Object> extensions = scheme.getExtensions();

            analyzeFlow("implicit", flows.getImplicit(), name, description, extensions, context, findings);
            analyzeFlow("authorization_code", flows.getAuthorizationCode(), name, description, extensions, context, findings);
            analyzeFlow("client_credentials", flows.getClientCredentials(), name, description, extensions, context, findings);
            analyzeFlow("password", flows.getPassword(), name, description, extensions, context, findings);
        });

        log.info("OAuth flows: {} findings", findings.size());
        return findings;
    }

    private static void analyzeFlow(String flowId,
                                    OAuthFlow flow,
                                    String schemeName,
                                    String schemeDescription,
                                    Map<String, Object> schemeExtensions,
                                    ContextAnalyzer.APIContext context,
                                    List<Vulnerability> findings) {
        if (flow == null) {
            return;
        }
        boolean highContext = context == ContextAnalyzer.APIContext.BANKING ||
            context == ContextAnalyzer.APIContext.GOVERNMENT ||
            context == ContextAnalyzer.APIContext.HEALTHCARE ||
            context == ContextAnalyzer.APIContext.TELECOM ||
            context == ContextAnalyzer.APIContext.AUTOMOTIVE;

        String flowDisplay = switch (flowId) {
            case "implicit" -> "Implicit";
            case "authorization_code" -> "Authorization Code";
            case "client_credentials" -> "Client Credentials";
            case "password" -> "Resource Owner Password";
            default -> flowId;
        };

        if (flowId.equals("implicit")) {
            findings.add(buildVulnerability(
                schemeName,
                "Используется небезопасный Implicit flow",
                "OAuth схема '" + schemeName + "' определяет Implicit flow. В OAuth 2.1 этот grant считается небезопасным, " +
                    "так как токены передаются через URL и могут утечь.",
                highSeverity(highContext),
                "Замените Implicit на Authorization Code + PKCE. " +
                    "Для SPA используйте public client с PKCE и короткоживущими токенами."
            ));
        }

        if (flowId.equals("password")) {
            findings.add(buildVulnerability(
                schemeName,
                "Используется устаревший Resource Owner Password flow",
                "Resource Owner Password Credentials (ROPC) передает логин/пароль напрямую и не рекомендован в современных API.",
                highContext ? Severity.HIGH : Severity.MEDIUM,
                "Откажитесь от ROPC. Используйте Authorization Code + PKCE. " +
                    "Если ROPC используется, ограничьте его для legacy клиентов, включите MFA и мониторинг."
            ));
        }

        evaluateEndpointUrl(flow.getAuthorizationUrl(), true, schemeName, flowDisplay, highContext, findings);
        evaluateEndpointUrl(flow.getTokenUrl(), false, schemeName, flowDisplay, highContext, findings);
        evaluateEndpointUrl(flow.getRefreshUrl(), false, schemeName, flowDisplay, highContext, findings);

        String flowText = buildFlowText(schemeDescription, flow);
        Map<String, String> scopes = flow.getScopes();
        if (scopes == null || scopes.isEmpty()) {
            findings.add(buildVulnerability(
                schemeName,
                flowDisplay + " без определённых scopes",
                "Grant '" + flowDisplay + "' не содержит scopes. Скопы нужны для минимизации прав доступа.",
                highSeverity(highContext),
                "Добавьте scopes в flow (например accounts:read, payments:write). Для PSD2 укажите точные полномочия."
            ));
        } else {
            checkScopes(scopes, schemeName, flowDisplay, highContext, findings);
            if (context == ContextAnalyzer.APIContext.BANKING) {
                boolean hasBankingScope = scopes.keySet().stream()
                    .map(String::toLowerCase)
                    .anyMatch(scope -> BANKING_REQUIRED_SCOPES.stream().anyMatch(scope::contains));
                if (!hasBankingScope) {
                    findings.add(buildVulnerability(
                        schemeName,
                        "PSD2/банковские scopes не определены",
                        "Grant '" + flowDisplay + "' не описывает специфические банковские scopes (accounts, payments, consents).",
                        Severity.HIGH,
                        "Для Open Banking укажите scopes согласно стандарту (например, accounts:read, payments:submit, fundsconfirmations:read)."
                    ));
                }
            }
        }

        if ("authorization_code".equals(flowId) && !containsAny(flowText, STATE_KEYWORDS)) {
            findings.add(buildVulnerability(
                schemeName,
                "Authorization Code без проверки state",
                "Схема '" + schemeName + "' не упоминает использование параметра state/anti-CSRF для Authorization Code. Без него возможна подмена redirect.",
                highSeverity(highContext),
                "Сделайте параметр state обязательным, генерируйте случайное значение на клиенте и проверяйте его на сервере. Опишите требование в спецификации."
            ));
        }

        boolean openIdScope = scopes != null && scopes.keySet().stream()
            .map(String::toLowerCase)
            .anyMatch(scope -> OPENID_KEYWORDS.stream().anyMatch(scope::contains));
        if ((flowId.equals("authorization_code") || flowId.equals("implicit")) && openIdScope && !containsAny(flowText, NONCE_KEYWORDS)) {
            findings.add(buildVulnerability(
                schemeName,
                "OpenID flow без nonce",
                "Grant '" + flowDisplay + "' с OpenID Connect scopes не описывает использование nonce. Это повышает риск replay атак при выдаче id_token.",
                highSeverity(highContext),
                "Добавьте требование nonce (S256) для всех OpenID запросов и проверку соответствия при выдаче id_token."
            ));
        }

        if ("authorization_code".equals(flowId)) {
            boolean pkceMentioned = containsPkceHint(schemeDescription) || containsPkceExtension(flow.getExtensions()) ||
                containsPkceExtension(schemeExtensions);
            if (!pkceMentioned) {
                findings.add(buildVulnerability(
                    schemeName,
                    "Authorization Code без явного PKCE",
                    "Схема '" + schemeName + "' описывает Authorization Code flow, но нет упоминаний PKCE/Proof Key. " +
                        "Без PKCE публичные клиенты уязвимы к code interception.",
                    highSeverity(highContext),
                    "Документируйте и внедрите обязательный PKCE (S256). " +
                        "Добавьте в описание: \"PKCE (S256) required\" или x-pkce-required: true."
                ));
            }
            if (!containsRedirectRestrictions(flow, schemeDescription)) {
                findings.add(buildVulnerability(
                    schemeName,
                    "Нет требований к валидации redirect_uri",
                    "Authorization Code flow не описывает правила проверки redirect_uri. " +
                        "Это позволяет подменять редиректы и красть авторизационный код.",
                    highContext ? Severity.HIGH : Severity.MEDIUM,
                    "Документируйте список разрешённых redirect_uri или требование exact match + HTTPS. " +
                        "Для банковских API соблюдайте требования PSD2 (регистрация redirect URI)."
                ));
            }
        }

        if ("client_credentials".equals(flowId) && highContext) {
            boolean hasStrongClientAuth = containsAny(flowText, MTLS_KEYWORDS) || containsAny(flowText, PRIVATE_KEY_JWT_KEYWORDS);
            if (!hasStrongClientAuth) {
                findings.add(buildVulnerability(
                    schemeName,
                    "Client Credentials без mTLS/private_key_jwt",
                    "Client Credentials flow используется для критичного контекста, но не описаны механизмы сильной аутентификации клиента (mTLS/private_key_jwt).",
                    Severity.HIGH,
                    "Обязательное требование: mutual TLS (RFC 8705) либо private_key_jwt. Документируйте хранение сертификатов, rotation секретов и контроль IP."
                ));
            }
        }
    }

    private static void evaluateEndpointUrl(String url,
                                            boolean isAuthorization,
                                            String schemeName,
                                            String flowDisplay,
                                            boolean highContext,
                                            List<Vulnerability> findings) {
        if (url == null || url.isBlank()) {
            if (isAuthorization || !flowDisplay.equals("Device Code")) {
                findings.add(buildVulnerability(
                    schemeName,
                    (isAuthorization ? "Authorization" : "Token") + " endpoint не указан",
                    "Flow '" + flowDisplay + "' в схеме '" + schemeName + "' не определяет " +
                        (isAuthorization ? "authorizationUrl" : "tokenUrl") + ".",
                    highSeverity(highContext),
                    "Укажите полный HTTPS URL. Это требуется для корректной интеграции и проверки безопасности."
                ));
            }
            return;
        }
        try {
            URI parsed = new URI(url);
            if (!"https".equalsIgnoreCase(parsed.getScheme())) {
                findings.add(buildVulnerability(
                    schemeName,
                    "OAuth endpoint без HTTPS",
                    "URL '" + url + "' в flow '" + flowDisplay + "' не использует HTTPS.",
                    highSeverity(highContext),
                    "Все OAuth endpoints должны быть доступны только по HTTPS."
                ));
            }
            if (parsed.getHost() != null) {
                String hostLower = parsed.getHost().toLowerCase(Locale.ROOT);
                if (hostLower.contains("localhost") || hostLower.equals("127.0.0.1")) {
                    findings.add(buildVulnerability(
                        schemeName,
                        "OAuth endpoint с localhost",
                        "URL '" + url + "' предназначен только для разработки. В production это недопустимо.",
                        highContext ? Severity.HIGH : Severity.MEDIUM,
                        "Используйте боевые домены и требуйте от клиентов зарегистрированные redirect_uri."
                    ));
                }
            }
        } catch (URISyntaxException ex) {
            findings.add(buildVulnerability(
                schemeName,
                "Некорректный OAuth endpoint URL",
                "URL '" + url + "' не соответствует URI синтаксису. Клиенты не смогут пройти авторизацию.",
                Severity.MEDIUM,
                "Исправьте URL или удалите устаревшие значения."
            ));
        }
    }

    private static void checkScopes(Map<String, String> scopes,
                                    String schemeName,
                                    String flowDisplay,
                                    boolean highContext,
                                    List<Vulnerability> findings) {
        for (String scope : scopes.keySet()) {
            String normalized = scope.trim().toLowerCase(Locale.ROOT);
            if (WILDCARD_SCOPES.contains(normalized) || normalized.endsWith(".*")) {
                findings.add(buildVulnerability(
                    schemeName,
                    "Небезопасный scope '" + scope + "'",
                    "Flow '" + flowDisplay + "' содержит слишком широкий scope '" + scope + "'. " +
                        "Это нарушает принцип наименьших привилегий.",
                    highSeverity(highContext),
                    "Разделите полномочия на конкретные scopes (например, accounts.read / accounts.write). " +
                        "Устраните wildcard-маски."
                ));
            }
        }
        String scopesText = String.join(", ", scopes.keySet());
        if (!scopesText.contains(":") && highContext) {
            findings.add(buildVulnerability(
                schemeName,
                "Scopes не содержат неймспейсов",
                "В банковском/гос контексте scopes должны быть строго типизированы (например, accounts:read). " +
                    "Сейчас scopes: " + scopesText,
                Severity.MEDIUM,
                "Используйте неймспейсы или стандартизованные scopes согласно профильному стандарту (Berlin Group, STET)."
            ));
        }
    }

    private static boolean containsPkceHint(String description) {
        if (description == null || description.isBlank()) {
            return false;
        }
        String lower = description.toLowerCase(Locale.ROOT);
        return lower.contains("pkce") || lower.contains("proof key") || lower.contains("code challenge");
    }

    private static boolean containsPkceExtension(Map<String, Object> extensions) {
        if (extensions == null || extensions.isEmpty()) {
            return false;
        }
        for (Map.Entry<String, Object> entry : extensions.entrySet()) {
            if (entry.getKey() == null) {
                continue;
            }
            String keyLower = entry.getKey().toLowerCase(Locale.ROOT);
            if (PKCE_EXTENSION_KEYS.stream().anyMatch(keyLower::contains)) {
                Object value = entry.getValue();
                if (value instanceof Boolean boolVal) {
                    return boolVal;
                }
                return true;
            }
        }
        return false;
    }

    private static boolean containsRedirectRestrictions(OAuthFlow flow, String description) {
        if (flow.getExtensions() != null) {
            for (Map.Entry<String, Object> entry : flow.getExtensions().entrySet()) {
                if (entry.getKey() != null && entry.getKey().toLowerCase(Locale.ROOT).contains("redirect") &&
                    entry.getValue() instanceof Collection<?> collection && !collection.isEmpty()) {
                    return true;
                }
            }
        }
        if (description == null) {
            return false;
        }
        String lower = description.toLowerCase(Locale.ROOT);
        return lower.contains("redirect_uri") && (lower.contains("whitelist") || lower.contains("exact match") ||
            lower.contains("https://") || lower.contains("allowlist"));
    }

    private static Severity highSeverity(boolean highContext) {
        return highContext ? Severity.CRITICAL : Severity.HIGH;
    }

    private static Vulnerability buildVulnerability(String schemeName,
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
                VulnerabilityType.BROKEN_AUTHENTICATION, "N/A", "N/A", schemeName, title))
            .type(VulnerabilityType.BROKEN_AUTHENTICATION)
            .severity(severity)
            .title(title)
            .description("OAuth схема '" + schemeName + "': " + description)
            .endpoint("components/securitySchemes/" + schemeName)
            .method("N/A")
            .recommendation("Рекомендация:\n" + recommendation)
            .owaspCategory("API2:2023 - Broken Authentication")
            .evidence("Scheme: " + schemeName)
            .confidence(ConfidenceCalculator.calculateConfidence(temp, null, false, true))
            .priority(ConfidenceCalculator.calculatePriority(temp,
                ConfidenceCalculator.calculateConfidence(temp, null, false, true)))
            .build();
    }

    private static String buildFlowText(String schemeDescription, OAuthFlow flow) {
        StringBuilder sb = new StringBuilder();
        if (schemeDescription != null) {
            sb.append(schemeDescription).append(' ');
        }
        if (flow.getAuthorizationUrl() != null) {
            sb.append(flow.getAuthorizationUrl()).append(' ');
        }
        if (flow.getTokenUrl() != null) {
            sb.append(flow.getTokenUrl()).append(' ');
        }
        if (flow.getRefreshUrl() != null) {
            sb.append(flow.getRefreshUrl()).append(' ');
        }
        if (flow.getScopes() != null && !flow.getScopes().isEmpty()) {
            flow.getScopes().forEach((scope, desc) -> {
                sb.append(scope).append(' ');
                if (desc != null) {
                    sb.append(desc).append(' ');
                }
            });
        }
        if (flow.getExtensions() != null) {
            flow.getExtensions().forEach((key, value) -> {
                if (key != null) {
                    sb.append(key).append(' ');
                }
                if (value != null) {
                    sb.append(String.valueOf(value)).append(' ');
                }
            });
        }
        return sb.toString().toLowerCase(Locale.ROOT);
    }

    private static boolean containsAny(String text, Set<String> keywords) {
        if (text == null || text.isBlank()) {
            return false;
        }
        String lower = text.toLowerCase(Locale.ROOT);
        for (String keyword : keywords) {
            if (lower.contains(keyword.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }
}
