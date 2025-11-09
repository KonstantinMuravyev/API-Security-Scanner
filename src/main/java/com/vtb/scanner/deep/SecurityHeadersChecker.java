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
 * Проверка Security Headers (РЕАЛЬНАЯ проверка спецификации!)
 * 
 * Критичные headers для безопасности:
 * - Strict-Transport-Security (HSTS)
 * - X-Frame-Options
 * - X-Content-Type-Options
 * - Content-Security-Policy
 * - X-XSS-Protection
 * - Permissions-Policy
 */
@Slf4j
public class SecurityHeadersChecker {
    
    // Критичные security headers
    private static final Map<String, String> REQUIRED_HEADERS = Map.of(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains",
        "X-Frame-Options", "DENY или SAMEORIGIN",
        "X-Content-Type-Options", "nosniff",
        "Content-Security-Policy", "default-src 'self'",
        "X-XSS-Protection", "1; mode=block"
    );
    
    /**
     * Проверить наличие security headers в responses
     */
    public static List<Vulnerability> checkSecurityHeaders(OpenAPI openAPI) {
        log.info("Проверка Security Headers...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) return vulnerabilities;
        
        boolean hasAnySecurityHeaders = false;
        Set<String> missingHeaders = new HashSet<>(REQUIRED_HEADERS.keySet());
        
        // Проверяем все эндпоинты
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            PathItem pathItem = entry.getValue();
            
            // Проверяем все методы
            List<Operation> operations = Arrays.asList(
                pathItem.getGet(), pathItem.getPost(), 
                pathItem.getPut(), pathItem.getDelete()
            );
            
            for (Operation op : operations) {
                if (op == null || op.getResponses() == null) continue;
                
                // Проверяем response headers
                for (ApiResponse response : op.getResponses().values()) {
                    if (response.getHeaders() != null) {
                        hasAnySecurityHeaders = true;
                        
                        for (String headerName : response.getHeaders().keySet()) {
                            missingHeaders.remove(headerName);
                        }
                    }
                }
            }
        }
        
        // Если нет НИ ОДНОГО security header
        if (!hasAnySecurityHeaders) {
            vulnerabilities.add(Vulnerability.builder()
                .id("SEC-HEADERS-NONE")
                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.HIGH)
                .title("Отсутствуют Security Headers")
                .description(
                    "API не определяет Security Headers в responses!\n\n" +
                    "Без них возможны атаки:\n" +
                    "• Clickjacking (нет X-Frame-Options)\n" +
                    "• MITM downgrade (нет HSTS)\n" +
                    "• XSS (нет CSP)\n" +
                    "• MIME sniffing (нет X-Content-Type-Options)"
                )
                .endpoint("N/A")
                .method("N/A")
                .recommendation(
                    "Добавьте Security Headers в спецификацию:\n\n" +
                    "responses:\n" +
                    "  '200':\n" +
                    "    headers:\n" +
                    "      Strict-Transport-Security:\n" +
                    "        schema:\n" +
                    "          type: string\n" +
                    "          example: max-age=31536000; includeSubDomains\n" +
                    "      X-Frame-Options:\n" +
                    "        schema:\n" +
                    "          type: string\n" +
                    "          example: DENY\n" +
                    "      Content-Security-Policy:\n" +
                    "        schema:\n" +
                    "          type: string\n" +
                    "          example: default-src 'self'\n" +
                    "      X-Content-Type-Options:\n" +
                    "        schema:\n" +
                    "          type: string\n" +
                    "          example: nosniff"
                )
                .owaspCategory("API8:2023 - Security Misconfiguration")
                .evidence("Нет ни одного security header в спецификации")
                .build());
        }
        
        // Какие конкретно headers отсутствуют
        for (String missing : missingHeaders) {
            if (!hasAnySecurityHeaders) break; // Уже сообщили что нет вообще
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.SECURITY_MISCONFIGURATION, "N/A", "N/A", missing,
                    "Отсутствует header: " + missing))
                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.MEDIUM)
                .title("Отсутствует header: " + missing)
                .description("Security header '" + missing + "' не определен.\n" +
                           "Рекомендуемое значение: " + REQUIRED_HEADERS.get(missing))
                .endpoint("N/A")
                .method("N/A")
                .recommendation("Добавьте header '" + missing + "' во все responses")
                .owaspCategory("API8:2023 - Security Misconfiguration")
                .evidence("Header отсутствует")
                .build());
        }
        
        log.info("Security Headers проверка завершена. Найдено проблем: {}", vulnerabilities.size());
        return vulnerabilities;
    }
}

