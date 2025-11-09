package com.vtb.scanner.deep;

import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.headers.Header;
import io.swagger.v3.oas.models.responses.ApiResponse;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * Проверка безопасности Cookies
 * 
 * Критичные атрибуты:
 * - HttpOnly (защита от XSS)
 * - Secure (только HTTPS)
 * - SameSite (защита от CSRF)
 */
@Slf4j
public class CookieSecurityChecker {
    
    public static List<Vulnerability> checkCookies(OpenAPI openAPI) {
        log.info("🍪 Проверка Cookie Security...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) return vulnerabilities;
        
        boolean foundCookies = false;
        boolean foundInsecureCookies = false;
        
        // Ищем Set-Cookie headers
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // Проверяем все методы (особенно login/auth)
            checkOperationCookies(path, "POST", pathItem.getPost(), vulnerabilities);
        }
        
        // Проверяем cookie-based auth в securitySchemes
        if (openAPI.getComponents() != null && 
            openAPI.getComponents().getSecuritySchemes() != null) {
            
            openAPI.getComponents().getSecuritySchemes().forEach((name, scheme) -> {
                if ("apiKey".equals(scheme.getType().toString()) && 
                    "cookie".equals(scheme.getIn() != null ? scheme.getIn().toString() : "")) {
                    
                    String desc = scheme.getDescription() != null ? scheme.getDescription().toLowerCase() : "";
                    
                    if (!desc.contains("httponly") || !desc.contains("secure") || !desc.contains("samesite")) {
                        vulnerabilities.add(Vulnerability.builder()
                            .id("COOKIE-INSECURE-" + name)
                            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                            .severity(Severity.HIGH)
                            .title("Cookie без security атрибутов")
                            .description(
                                "Cookie '" + name + "' не описывает security атрибуты!\n\n" +
                                "Отсутствуют:\n" +
                                (!desc.contains("httponly") ? "• HttpOnly (защита от XSS)\n" : "") +
                                (!desc.contains("secure") ? "• Secure (только HTTPS)\n" : "") +
                                (!desc.contains("samesite") ? "• SameSite (защита от CSRF)\n" : "")
                            )
                            .endpoint("N/A")
                            .method("N/A")
                            .recommendation(
                                "Установите security атрибуты для cookies:\n\n" +
                                "Set-Cookie: session=...; \n" +
                                "  HttpOnly;        // Защита от XSS\n" +
                                "  Secure;          // Только HTTPS\n" +
                                "  SameSite=Strict; // Защита от CSRF\n" +
                                "  Max-Age=3600;    // Время жизни\n" +
                                "  Path=/;          // Область действия"
                            )
                            .owaspCategory("API8:2023 - Security Misconfiguration")
                            .evidence("Cookie без HttpOnly/Secure/SameSite")
                            .build());
                    }
                }
            });
        }
        
        log.info("Cookie Security проверка завершена. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private static void checkOperationCookies(String path, String method, Operation operation,
                                             List<Vulnerability> vulnerabilities) {
        if (operation == null || operation.getResponses() == null) return;
        
        for (ApiResponse response : operation.getResponses().values()) {
            if (response.getHeaders() == null) continue;
            
            // Ищем Set-Cookie
            for (Map.Entry<String, Header> headerEntry : response.getHeaders().entrySet()) {
                if (headerEntry.getKey().equalsIgnoreCase("Set-Cookie")) {
                    Header header = headerEntry.getValue();
                    String desc = header.getDescription() != null ? header.getDescription().toLowerCase() : "";
                    
                    // Проверяем атрибуты
                    if (!desc.contains("httponly")) {
                        vulnerabilities.add(createCookieVulnerability(
                            path, method, "HttpOnly",
                            "Cookie без HttpOnly - уязвим к XSS!",
                            Severity.HIGH
                        ));
                    }
                    
                    if (!desc.contains("secure")) {
                        vulnerabilities.add(createCookieVulnerability(
                            path, method, "Secure",
                            "Cookie без Secure - может быть перехвачен через HTTP!",
                            Severity.HIGH
                        ));
                    }
                    
                    if (!desc.contains("samesite")) {
                        vulnerabilities.add(createCookieVulnerability(
                            path, method, "SameSite",
                            "Cookie без SameSite - уязвим к CSRF!",
                            Severity.MEDIUM
                        ));
                    }
                }
            }
        }
    }
    
    private static Vulnerability createCookieVulnerability(String path, String method, 
                                                           String attribute, String description,
                                                           Severity severity) {
        return Vulnerability.builder()
            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, attribute,
                "Cookie без " + attribute))
            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
            .severity(severity)
            .title("Cookie без " + attribute)
            .description(description)
            .endpoint(path)
            .method(method)
            .recommendation("Добавьте " + attribute + " атрибут к cookie")
            .owaspCategory("API8:2023 - Security Misconfiguration")
            .evidence("Set-Cookie без " + attribute)
            .build();
    }
}

