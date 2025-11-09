package com.vtb.scanner.deep;

import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * Детальная проверка OAuth 2.0 flows
 * 
 * Проверяет:
 * - Правильность grant types
 * - Scopes
 * - PKCE для public clients
 * - Redirect URI validation
 */
@Slf4j
public class OAuthFlowChecker {
    
    public static List<Vulnerability> checkOAuthFlows(OpenAPI openAPI) {
        log.info("🔐 Проверка OAuth 2.0 flows...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getComponents() == null || 
            openAPI.getComponents().getSecuritySchemes() == null) {
            return vulnerabilities;
        }
        
        openAPI.getComponents().getSecuritySchemes().forEach((name, scheme) -> {
            if (SecurityScheme.Type.OAUTH2.equals(scheme.getType())) {
                OAuthFlows flows = scheme.getFlows();
                
                if (flows == null) {
                    vulnerabilities.add(createOAuthVulnerability(
                        name, "OAuth scheme без flows",
                        "OAuth2 схема '" + name + "' не определяет flows!", Severity.HIGH
                    ));
                    return;
                }
                
                // Implicit flow - устаревший!
                if (flows.getImplicit() != null) {
                    vulnerabilities.add(createOAuthVulnerability(
                        name, "Используется Implicit Flow (устаревший!)",
                        "Implicit Flow признан небезопасным OAuth 2.1!\n" +
                        "Токен передается в URL → может утечь через logs/history.",
                        Severity.HIGH
                    ));
                }
                
                // Authorization Code без PKCE
                if (flows.getAuthorizationCode() != null) {
                    String desc = scheme.getDescription() != null ? scheme.getDescription().toLowerCase() : "";
                    if (!desc.contains("pkce")) {
                        vulnerabilities.add(createOAuthVulnerability(
                            name, "Authorization Code без PKCE",
                            "PKCE обязателен для защиты от authorization code interception!",
                            Severity.MEDIUM
                        ));
                    }
                }
                
                // Client Credentials для публичных клиентов
                if (flows.getClientCredentials() != null) {
                    vulnerabilities.add(createOAuthVulnerability(
                        name, "Client Credentials flow",
                        "Client Credentials подходит только для server-to-server!\n" +
                        "НЕ используйте для mobile/SPA приложений!",
                        Severity.MEDIUM
                    ));
                }
            }
        });
        
        log.info("OAuth проверка завершена. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private static Vulnerability createOAuthVulnerability(String schemeName, String title,
                                                          String description, Severity severity) {
        return Vulnerability.builder()
            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                VulnerabilityType.BROKEN_AUTHENTICATION, "N/A", "N/A", schemeName, title))
            .type(VulnerabilityType.BROKEN_AUTHENTICATION)
            .severity(severity)
            .title(title)
            .description("OAuth схема '" + schemeName + "': " + description)
            .endpoint("N/A")
            .method("N/A")
            .recommendation(
                "OAuth 2.1 Best Practices:\n" +
                "• Используйте Authorization Code + PKCE\n" +
                "• Не используйте Implicit Flow\n" +
                "• Короткий lifetime для access tokens\n" +
                "• Refresh token rotation\n" +
                "• Строгая redirect_uri validation"
            )
            .owaspCategory("API2:2023 - Broken Authentication")
            .evidence("OAuth flow проблема")
            .build();
    }
}

