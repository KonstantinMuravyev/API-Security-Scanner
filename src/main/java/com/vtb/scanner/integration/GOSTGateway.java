package com.vtb.scanner.integration;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.semantic.ContextAnalyzer;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;

import java.io.IOException;
import java.util.*;


/**
 * Интеграция с ГОСТ-шлюзом
 * Проверка соответствия российским стандартам безопасности
 * 
 * ГОСТ Р 34.10-2012 - Процессы формирования и проверки электронной цифровой подписи
 *   (российский стандарт ЭЦП, альтернатива RSA/ECDSA)
 * 
 * ГОСТ Р 34.11-2012 (Стрибог) - Функция хэширования
 *   (российский хэш-алгоритм, альтернатива SHA-256)
 * 
 * ГОСТ 28147-89 (Магма) - Блочное шифрование
 *   (устаревший, но всё ещё используется)
 * 
 * ФЗ-152 - О персональных данных
 *   Требует защиты ПДн российскими сертифицированными средствами
 */
@Slf4j
public class GOSTGateway {
    
    private final String gatewayUrl;
    private final OkHttpClient httpClient;
    
    // Поля, считающиеся персональными данными по ФЗ-152
    private static final List<String> PERSONAL_DATA_FIELDS = List.of(
        "name", "surname", "lastname", "firstname", "middlename",
        "email", "phone", "passport", "inn", "snils",
        "address", "birthdate", "birthday", "birthplace"
    );
    
    // ГОСТ алгоритмы криптографии
    private static final Set<String> GOST_ALGORITHMS = Set.of(
        "gost", "гост", "gostr3410", "gostr3411", "gostr34102012",
        "gostr34112012", "gost28147", "streebog", "стрибог", "магма"
    );
    
    // Международные алгоритмы (для контраста)
    private static final Set<String> INTERNATIONAL_ALGORITHMS = Set.of(
        "rsa", "ecdsa", "sha256", "sha-256", "sha512", "aes"
    );
    
    /**
     * Автоматически определить нужно ли проверять ГОСТ
     * 
     * Проверяет:
     * 1. Явное упоминание ГОСТ в спецификации
     * 2. Контекст API (банк, госуслуги требуют ГОСТ)
     * 3. Домен (.ru, .рф)
     * 4. ФЗ-152 (персональные данные)
     */
    public static boolean shouldCheckGOST(OpenAPI openAPI, String targetUrl) {
        if (openAPI == null) {
            return false;
        }
        
        // 1. Проверка упоминания ГОСТ в спецификации
        String description = openAPI.getInfo() != null && 
            openAPI.getInfo().getDescription() != null ?
            openAPI.getInfo().getDescription().toLowerCase() : "";
        String title = openAPI.getInfo() != null && 
            openAPI.getInfo().getTitle() != null ?
            openAPI.getInfo().getTitle().toLowerCase() : "";
        
        String combined = (description + " " + title).toLowerCase();
        
        boolean mentionsGOST = combined.contains("гост") || 
                               combined.contains("gost") ||
                               combined.contains("34.10") ||
                               combined.contains("34.11") ||
                               combined.contains("34.12") ||
                               combined.contains("стрибог") ||
                               combined.contains("streebog") ||
                               combined.contains("кузнечик") ||
                               combined.contains("kuznyechik") ||
                               combined.contains("магма") ||
                               combined.contains("magma");
        
        if (mentionsGOST) {
            log.debug("ГОСТ обнаружен в спецификации");
            return true;
        }
        
        // 2. Проверка контекста API
        ContextAnalyzer.APIContext context =
            ContextAnalyzer.detectContext(openAPI);
        
        if (context == ContextAnalyzer.APIContext.BANKING ||
            context == ContextAnalyzer.APIContext.GOVERNMENT) {
            log.debug("ГОСТ требуется для контекста: {}", context);
            return true;
        }
        
        // 3. Проверка домена (.ru, .рф)
        if (targetUrl != null) {
            String urlLower = targetUrl.toLowerCase();
            if (urlLower.contains(".ru") || urlLower.contains(".рф") ||
                urlLower.contains(".su") || urlLower.contains(".ru.com")) {
                log.debug("ГОСТ рекомендуется для российского домена");
                // Для .ru доменов - рекомендуем, но не требуем
                // Если явно указан --gost, будем проверять строго
                return false; // Автоматически не включаем, но рекомендуем
            }
        }
        
        // 4. Проверка персональных данных (ФЗ-152)
        if (combined.contains("персональн") || combined.contains("personal") ||
            combined.contains("паспорт") || combined.contains("passport") ||
            combined.contains("инн") || combined.contains("inn") ||
            combined.contains("снилс") || combined.contains("snils")) {
            log.debug("ГОСТ рекомендуется для обработки персональных данных (ФЗ-152)");
            return false; // Рекомендуем, но не требуем автоматически
        }
        
        return false;
    }
    
    /**
     * Проверить соответствует ли спецификация ГОСТ требованиям
     * Используется для валидации когда пользователь явно указал --gost
     */
    public static boolean isGOSTCompliant(OpenAPI openAPI) {
        if (openAPI == null) {
            return false;
        }
        
        String description = openAPI.getInfo() != null && 
            openAPI.getInfo().getDescription() != null ?
            openAPI.getInfo().getDescription().toLowerCase() : "";
        String title = openAPI.getInfo() != null && 
            openAPI.getInfo().getTitle() != null ?
            openAPI.getInfo().getTitle().toLowerCase() : "";
        
        String combined = (description + " " + title).toLowerCase();
        
        // Проверяем упоминание ГОСТ алгоритмов
        return combined.contains("гост") || 
               combined.contains("gost") ||
               combined.contains("34.10") ||
               combined.contains("34.11") ||
               combined.contains("34.12") ||
               combined.contains("стрибог") ||
               combined.contains("streebog");
    }
    
    /**
     * @param gatewayUrl URL ГОСТ-шлюза. Если не указан — выполняются только локальные проверки.
     */
    public GOSTGateway(String gatewayUrl) {
        this.gatewayUrl = (gatewayUrl != null && !gatewayUrl.isBlank()) ? gatewayUrl : null;
        this.httpClient = new OkHttpClient.Builder().build();
        
        if (this.gatewayUrl == null) {
            log.info("ГОСТ-шлюз не указан – выполняем локальные проверки без внешнего сервиса.");
        } else {
            log.info("ГОСТ Gateway URL: {}", gatewayUrl);
        }
    }
    
    /**
     * Выполнить ГЛУБОКУЮ проверку ГОСТ стандартов
     * 
     * ВСЕГДА проверяем ГОСТ! Неважно российский API или нет!
     * Для банков это КРИТИЧНО!
     */
    public List<Vulnerability> checkGostCompliance(OpenAPI openAPI, OpenAPIParser parser, String targetUrl) {
        log.info("=== Запуск ГЛУБОКОЙ ГОСТ проверки ===");
        log.info("Проверяем всегда! Для банковского сектора ГОСТ обязателен!");
        
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // 1. Проверка криптографии в спецификации (базовая)
        vulnerabilities.addAll(checkCryptographyStandards(openAPI));
        
        // 1b. Уязвимости В ГОСТ системах (базовые)
        vulnerabilities.addAll(com.vtb.scanner.deep.GOSTVulnerabilityChecker.findGOSTVulnerabilities(openAPI));
        
        // 1c. ГЛУБОКИЙ анализ ГОСТ (10 проверок!)
        log.info("🔬 ГЛУБОКИЙ анализ ГОСТ: стандарты, параметры, реализация, ключи...");
        vulnerabilities.addAll(com.vtb.scanner.gost.GOSTDeepAnalyzer.deepAnalyze(openAPI));
        
        // 2. Проверка персональных данных (ФЗ-152) - ДЕТАЛЬНО!
        vulnerabilities.addAll(checkPersonalDataProtection(openAPI, parser));
        
        // 3. Проверка транспортной безопасности
        vulnerabilities.addAll(checkTransportSecurity(openAPI));
        
        // 4. РЕАЛЬНАЯ проверка TLS (если HTTPS) - САМОЕ ВАЖНОЕ!
        if (targetUrl != null && targetUrl.startsWith("https://")) {
            log.info("Запуск РЕАЛЬНОЙ ГОСТ TLS проверки...");
            log.info("⚡ Подключаемся к серверу для анализа криптографии...");
            ContextAnalyzer.APIContext context = ContextAnalyzer.detectContext(openAPI);
            boolean enforceGost = context == ContextAnalyzer.APIContext.BANKING ||
                context == ContextAnalyzer.APIContext.GOVERNMENT ||
                context == ContextAnalyzer.APIContext.HEALTHCARE;
            TLSAnalyzer tlsAnalyzer = new TLSAnalyzer(targetUrl, context, enforceGost);
            vulnerabilities.addAll(tlsAnalyzer.analyzeTLS());
        } else if (targetUrl != null && targetUrl.startsWith("http://")) {
            // HTTP вместо HTTPS - КРИТИЧНО для ГОСТ!
            vulnerabilities.add(Vulnerability.builder()
                .id("GOST-HTTP-NOT-HTTPS")
                .type(VulnerabilityType.GOST_VIOLATION)
                .severity(Severity.CRITICAL)
                .title("КРИТИЧНО! Используется HTTP вместо HTTPS")
                .description(
                    "API использует незащищенный протокол HTTP!\n\n" +
                    "Это НАРУШАЕТ:\n" +
                    "• ФЗ-152 (персональные данные должны быть защищены)\n" +
                    "• Требования ЦБ РФ (банки обязаны использовать TLS)\n" +
                    "• Приказ ФСБ России №378\n\n" +
                    "Данные передаются в открытом виде - возможен перехват!"
                )
                .endpoint(targetUrl)
                .method("N/A")
                .recommendation(
                    "НЕМЕДЛЕННО настройте HTTPS с ГОСТ:\n\n" +
                    "1. Получите сертификат от российского УЦ\n" +
                    "2. Настройте TLS 1.2+ с ГОСТ cipher suites\n" +
                    "3. Перенаправляйте HTTP → HTTPS (301 redirect)\n" +
                    "4. Используйте HSTS header"
                )
                .owaspCategory("Russian Standards - ГОСТ (CRITICAL)")
                .evidence("Server URL: " + targetUrl + " (HTTP!)")
                .gostRelated(true)
                .build());
        }
        
        // 5. Проверка через реальный ГОСТ-шлюз (если доступен)
        if (gatewayUrl != null) {
            log.info("Проверка через внешний ГОСТ-шлюз: {}", gatewayUrl);
            vulnerabilities.addAll(checkViaGateway(openAPI));
        }
        
        log.info("ГОСТ проверка завершена. Найдено нарушений: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    /**
     * Проверка соответствия стандартам криптографии ГОСТ
     */
    private List<Vulnerability> checkCryptographyStandards(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getComponents() == null || 
            openAPI.getComponents().getSecuritySchemes() == null) {
            
            // Нет security schemes вообще
            vulnerabilities.add(Vulnerability.builder()
                .id("GOST-NO-SCHEMES")
                .type(VulnerabilityType.GOST_VIOLATION)
                .severity(Severity.HIGH)
                .title("Отсутствуют схемы безопасности")
                .description(
                    "В API нет определенных securitySchemes. " +
                    "Для соответствия требованиям информационной безопасности РФ " +
                    "необходимо использовать ГОСТ криптографию."
                )
                .endpoint("N/A")
                .method("N/A")
                .recommendation(
                    "Добавьте security schemes с использованием:\n" +
                    "- ГОСТ Р 34.10-2012 для ЭЦП\n" +
                    "- ГОСТ Р 34.11-2012 (Стрибог) для хэширования\n" +
                    "- ГОСТ 28147-89 или современные алгоритмы для шифрования"
                )
                .owaspCategory("Russian Standards - GOST")
                .evidence("components.securitySchemes отсутствует")
                .gostRelated(true)
                .build());
            
            return vulnerabilities;
        }
        
        Map<String, SecurityScheme> schemes = openAPI.getComponents().getSecuritySchemes();
        boolean hasAnyGost = false;
        boolean hasInternationalOnly = false;
        
        for (Map.Entry<String, SecurityScheme> entry : schemes.entrySet()) {
            String schemeName = entry.getKey();
            SecurityScheme scheme = entry.getValue();
            
            String description = (scheme.getDescription() != null ? scheme.getDescription() : "").toLowerCase();
            String schemeNameLower = schemeName.toLowerCase();
            
            // Проверяем упоминание ГОСТ
            boolean hasGost = GOST_ALGORITHMS.stream()
                .anyMatch(algo -> description.contains(algo) || schemeNameLower.contains(algo));
            
            // Проверяем упоминание международных алгоритмов
            boolean hasInternational = INTERNATIONAL_ALGORITHMS.stream()
                .anyMatch(algo -> description.contains(algo) || schemeNameLower.contains(algo));
            
            if (hasGost) {
                hasAnyGost = true;
            }
            
            if (hasInternational && !hasGost) {
                hasInternationalOnly = true;
                
                vulnerabilities.add(Vulnerability.builder()
                    .id("GOST-INTL-" + schemeName)
                    .type(VulnerabilityType.GOST_VIOLATION)
                    .severity(Severity.MEDIUM)
                    .title("Использование только международных алгоритмов")
                    .description(String.format(
                        "Схема '%s' использует международные алгоритмы (%s), " +
                        "но не упоминает ГОСТ. Для государственных систем и критичной " +
                        "инфраструктуры РФ требуется использование ГОСТ криптографии.",
                        schemeName, description.contains("rsa") ? "RSA" : 
                                    description.contains("ecdsa") ? "ECDSA" : "международные"
                    ))
                    .endpoint("N/A")
                    .method("N/A")
                    .recommendation(
                        "Рассмотрите использование ГОСТ Р 34.10-2012 вместо/вместе с RSA/ECDSA. " +
                        "Для систем, работающих с гос. данными, ГОСТ обязателен. " +
                        "Можно поддерживать оба стандарта одновременно."
                    )
                    .owaspCategory("Russian Standards - GOST")
                    .evidence("Упомянуты: " + description)
                    .gostRelated(true)
                    .build());
            }
            
            // Если используется HTTP схема без упоминания алгоритмов
            if (scheme.getType() == SecurityScheme.Type.HTTP && 
                !hasGost && !hasInternational &&
                (description.isEmpty() || description.length() < 20)) {
                
                vulnerabilities.add(Vulnerability.builder()
                    .id("GOST-NO-DETAILS-" + schemeName)
                    .type(VulnerabilityType.GOST_VIOLATION)
                    .severity(Severity.LOW)
                    .title("Не указаны криптографические алгоритмы")
                    .description(String.format(
                        "Схема '%s' не описывает используемые криптографические алгоритмы. " +
                        "Не ясно, соответствует ли она российским стандартам.",
                        schemeName
                    ))
                    .endpoint("N/A")
                    .method("N/A")
                    .recommendation(
                        "Укажите в описании схемы используемые алгоритмы. " +
                        "Для России: ГОСТ Р 34.10-2012, ГОСТ Р 34.11-2012."
                    )
                    .owaspCategory("Russian Standards - GOST")
                    .evidence("Описание отсутствует или слишком краткое")
                    .gostRelated(true)
                    .build());
            }
        }
        
        // Итоговая проверка
        if (!hasAnyGost && hasInternationalOnly) {
            vulnerabilities.add(Vulnerability.builder()
                .id("GOST-NONE")
                .type(VulnerabilityType.GOST_VIOLATION)
                .severity(Severity.HIGH)
                .title("API не использует ГОСТ криптографию")
                .description(
                    "В спецификации API не найдено упоминаний ГОСТ алгоритмов. " +
                    "Для соответствия требованиям ФСБ России и работы с защищенными " +
                    "государственными системами требуется использование ГОСТ."
                )
                .endpoint("N/A")
                .method("N/A")
                .recommendation(
                    "Добавьте поддержку российской криптографии:\n" +
                    "• ГОСТ Р 34.10-2012 - для электронной подписи\n" +
                    "• ГОСТ Р 34.11-2012 (Стрибог) - для хэширования\n" +
                    "• TLS с ГОСТ cipher suites для транспорта\n\n" +
                    "Библиотеки: OpenSSL + engine_gost, CryptoPro"
                )
                .owaspCategory("Russian Standards - GOST")
                .evidence("Найдены только международные алгоритмы, ГОСТ отсутствует")
                .gostRelated(true)
                .build());
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка защиты персональных данных (ФЗ-152)
     */
    private List<Vulnerability> checkPersonalDataProtection(OpenAPI openAPI, OpenAPIParser parser) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || parser == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            
            // Проверяем все операции
            Map<String, Operation> operations = parser.getOperationsForPath(path);
            
            for (Map.Entry<String, Operation> opEntry : operations.entrySet()) {
                String method = opEntry.getKey();
                Operation operation = opEntry.getValue();
                
                if (operation == null) continue;
                
                // Проверяем response schemas на персональные данные
                String opDesc = (operation.getDescription() != null ? operation.getDescription() : "") +
                               (operation.getSummary() != null ? operation.getSummary() : "");
                String opDescLower = opDesc.toLowerCase();
                
                boolean hasPersonalData = PERSONAL_DATA_FIELDS.stream()
                    .anyMatch(opDescLower::contains) ||
                    com.vtb.scanner.util.AccessControlHeuristics.mentionsPersonalData(operation);
                
                if (hasPersonalData) {
                    boolean requiresAuth = parser.requiresAuthentication(operation);
                    boolean explicitAccess = com.vtb.scanner.util.AccessControlHeuristics.hasExplicitAccessControl(operation, path, openAPI);
                    
                    if (!requiresAuth || !explicitAccess) {
                        vulnerabilities.add(Vulnerability.builder()
                            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                                VulnerabilityType.FZ152_VIOLATION, path, method, null,
                                "Нарушение ФЗ-152: персональные данные без защиты"))
                            .type(VulnerabilityType.FZ152_VIOLATION)
                            .severity(Severity.CRITICAL)
                            .title("Нарушение ФЗ-152: персональные данные без защиты")
                            .description("Эндпоинт " + path + " обрабатывает персональные данные, " +
                                       "но не защищен аутентификацией")
                            .endpoint(path)
                            .method(method)
                            .recommendation("Согласно ФЗ-152, персональные данные должны быть защищены. " +
                                          "Добавьте аутентификацию и шифрование для этого эндпоинта")
                            .owaspCategory("Russian Standards - ФЗ-152")
                            .evidence("Обнаружены поля персональных данных без должной защиты")
                            .gostRelated(true)
                            .build());
                    }
                    
                    // Проверяем HTTPS
                    if (openAPI.getServers() != null && !openAPI.getServers().isEmpty() && 
                        openAPI.getServers().get(0) != null) {
                        String serverUrl = openAPI.getServers().get(0).getUrl();
                        if (serverUrl != null && serverUrl.startsWith("http://")) {
                            vulnerabilities.add(Vulnerability.builder()
                                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                                    VulnerabilityType.FZ152_VIOLATION, path, method, null,
                                    "Нарушение ФЗ-152: передача персональных данных по HTTP"))
                                .type(VulnerabilityType.FZ152_VIOLATION)
                                .severity(Severity.HIGH)
                                .title("Нарушение ФЗ-152: передача персональных данных по HTTP")
                                .description("Персональные данные передаются по незащищенному протоколу HTTP")
                                .endpoint(path)
                                .method(method)
                                .recommendation("Используйте HTTPS для всех эндпоинтов, работающих с " +
                                              "персональными данными (требование ФЗ-152)")
                                .owaspCategory("Russian Standards - ФЗ-152")
                                .evidence("Server URL начинается с http://")
                                .gostRelated(true)
                                .build());
                        }
                    }
                }
            }
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка транспортной безопасности
     */
    private List<Vulnerability> checkTransportSecurity(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI != null && openAPI.getServers() != null && !openAPI.getServers().isEmpty() &&
            openAPI.getServers().get(0) != null) {
            String serverUrl = openAPI.getServers().get(0).getUrl();
            
            if (serverUrl != null && serverUrl.startsWith("http://")) {
                vulnerabilities.add(Vulnerability.builder()
                    .id("GOST-TLS")
                    .type(VulnerabilityType.GOST_VIOLATION)
                    .severity(Severity.HIGH)
                    .title("Отсутствует защищенное соединение")
                    .description("API использует незащищенный протокол HTTP вместо HTTPS")
                    .endpoint("N/A")
                    .method("N/A")
                    .recommendation("Используйте HTTPS с поддержкой TLS 1.2+ и желательно " +
                                  "с ГОСТ-совместимыми cipher suites")
                    .owaspCategory("Russian Standards - GOST")
                    .evidence("Server URL: " + serverUrl)
                    .gostRelated(true)
                    .build());
            }
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка через реальный ГОСТ-шлюз
     */
    private List<Vulnerability> checkViaGateway(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        try {
            String payload = io.swagger.v3.core.util.Json.mapper().writeValueAsString(openAPI);
            RequestBody body = RequestBody.create(
                payload,
                MediaType.get("application/json")
            );

            log.info("Отправка запроса на ГОСТ-шлюз: {}", gatewayUrl);
            
            Request request = new Request.Builder()
                .url(gatewayUrl + "/api/check")
                .post(body)
                .build();
            
            try (Response response = httpClient.newCall(request).execute()) {
                if (response.isSuccessful()) {
                    log.info("ГОСТ-шлюз ответил успешно");
                    // Парсим ответ и добавляем уязвимости
                } else {
                    log.warn("ГОСТ-шлюз вернул ошибку: {}", response.code());
                }
            }
            
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            log.error("Не удалось сериализовать OpenAPI для ГОСТ-шлюза: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Ошибка при обращении к ГОСТ-шлюзу: {}", e.getMessage());
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверить является ли ГОСТ-шлюз доступным
     */
    public boolean isGatewayAvailable() {
        if (gatewayUrl == null) {
            return false;
        }
        
        try {
            Request request = new Request.Builder()
                .url(gatewayUrl + "/health")
                .get()
                .build();
            
            try (Response response = httpClient.newCall(request).execute()) {
                return response.isSuccessful();
            }
        } catch (IOException e) {
            log.error("ГОСТ-шлюз недоступен: {}", e.getMessage());
            return false;
        }
    }
}

