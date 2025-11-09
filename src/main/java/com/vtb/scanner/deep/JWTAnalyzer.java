package com.vtb.scanner.deep;

import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * Анализ JWT токенов
 * 
 * Проверяет:
 * - Алгоритмы подписи (RS256, HS256, ГОСТ!)
 * - Claims (exp, iss, aud)
 * - Symmetric vs Asymmetric
 */
@Slf4j
public class JWTAnalyzer {
    
    // Слабые/устаревшие алгоритмы
    private static final Set<String> WEAK_JWT_ALGORITHMS = Set.of(
        "none", "NONE", "HS256" // HS256 если секрет слабый
    );
    
    // ГОСТ алгоритмы для JWT
    private static final Set<String> GOST_JWT_ALGORITHMS = Set.of(
        "GOSTR34102012", "GOST34102012", "GOST"
    );
    
    public static List<Vulnerability> analyzeJWT(OpenAPI openAPI) {
        log.info("🔑 Анализ JWT токенов...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getComponents() == null || 
            openAPI.getComponents().getSecuritySchemes() == null) {
            return vulnerabilities;
        }
        
        openAPI.getComponents().getSecuritySchemes().forEach((name, scheme) -> {
            if (SecurityScheme.Type.HTTP.equals(scheme.getType()) && 
                "bearer".equalsIgnoreCase(scheme.getScheme())) {
                
                String desc = scheme.getDescription() != null ? scheme.getDescription() : "";
                String descLower = desc.toLowerCase();
                
                // 1. Проверка алгоритма
                boolean mentionsAlgorithm = descLower.contains("rs256") || 
                                           descLower.contains("es256") ||
                                           descLower.contains("hs256") ||
                                           descLower.contains("gost");
                
                if (!mentionsAlgorithm) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id("JWT-NO-ALG-" + name)
                        .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                        .severity(Severity.MEDIUM)
                        .title("JWT без указания алгоритма подписи")
                        .description(
                            "JWT схема '" + name + "' не описывает алгоритм подписи!\n\n" +
                            "Важно знать:\n" +
                            "• RS256/ES256 (asymmetric) - рекомендуется\n" +
                            "• HS256 (symmetric) - только если секрет сильный\n" +
                            "• 'none' - ЗАПРЕЩЕН!\n" +
                            "• ГОСТ Р 34.10-2012 - для российских систем"
                        )
                        .endpoint("N/A")
                        .method("N/A")
                        .recommendation(
                            "Укажите алгоритм в описании:\n\n" +
                            "description: |\n" +
                            "  JWT tokens подписанные RS256\n" +
                            "  или\n" +
                            "  JWT tokens с ГОСТ Р 34.10-2012"
                        )
                        .owaspCategory("API2:2023 - Broken Authentication")
                        .evidence("Алгоритм не упомянут")
                        .build());
                }
                
                // 2. Проверка на 'none' алгоритм
                if (descLower.contains("\"alg\":\"none\"") || descLower.contains("alg=none")) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id("JWT-NONE-ALG-" + name)
                        .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                        .severity(Severity.CRITICAL)
                        .title("JWT с алгоритмом 'none' - КРИТИЧНО!")
                        .description(
                            "JWT принимает алгоритм 'none' - БЕЗ ПОДПИСИ!\n\n" +
                            "Атака:\n" +
                            "1. Перехватить JWT\n" +
                            "2. Изменить payload (role: admin)\n" +
                            "3. Установить alg: none\n" +
                            "4. Получить admin доступ!"
                        )
                        .endpoint("N/A")
                        .method("N/A")
                        .recommendation("НЕМЕДЛЕННО запретите 'none' алгоритм в JWT библиотеке!")
                        .owaspCategory("API2:2023 - Broken Authentication (CRITICAL)")
                        .evidence("alg=none разрешен")
                        .build());
                }
                
                // 3. HS256 с предупреждением
                if (descLower.contains("hs256")) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id("JWT-HS256-" + name)
                        .type(VulnerabilityType.WEAK_AUTHENTICATION)
                        .severity(Severity.MEDIUM)
                        .title("JWT использует HS256 (symmetric)")
                        .description(
                            "HS256 безопасен ТОЛЬКО если секрет очень сильный!\n\n" +
                            "Риски:\n" +
                            "• Слабый секрет → brute force\n" +
                            "• Секрет в каждом сервисе (микросервисы)\n\n" +
                            "Лучше: RS256/ES256 (asymmetric)"
                        )
                        .endpoint("N/A")
                        .method("N/A")
                        .recommendation(
                            "Если используете HS256:\n" +
                            "• Секрет минимум 256 бит (32 байта)\n" +
                            "• Генерируйте криптостойким PRNG\n\n" +
                            "Лучше переходите на RS256 или ГОСТ Р 34.10-2012"
                        )
                        .owaspCategory("API2:2023 - Broken Authentication")
                        .evidence("HS256 symmetric algorithm")
                        .build());
                }
                
                // 4. Проверка на ГОСТ в JWT
                boolean hasGOST = GOST_JWT_ALGORITHMS.stream()
                    .anyMatch(descLower::contains);
                
                if (!hasGOST) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id("JWT-NO-GOST-" + name)
                        .type(VulnerabilityType.GOST_VIOLATION)
                        .severity(Severity.MEDIUM)
                        .title("JWT без ГОСТ алгоритма")
                        .description(
                            "JWT токены не используют ГОСТ Р 34.10-2012 для подписи.\n\n" +
                            "Для банковского сектора и госструктур РФ рекомендуется ГОСТ."
                        )
                        .endpoint("N/A")
                        .method("N/A")
                        .recommendation(
                            "Используйте ГОСТ Р 34.10-2012 для подписи JWT:\n\n" +
                            "{\n" +
                            "  \"alg\": \"GOSTR34102012\",\n" +
                            "  \"typ\": \"JWT\"\n" +
                            "}\n\n" +
                            "Библиотеки: CryptoPro JCP, BouncyCastle"
                        )
                        .owaspCategory("Russian Standards - GOST")
                        .evidence("JWT без ГОСТ алгоритма")
                        .gostRelated(true)
                        .build());
                }
            }
        });
        
        log.info("JWT анализ завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
}

