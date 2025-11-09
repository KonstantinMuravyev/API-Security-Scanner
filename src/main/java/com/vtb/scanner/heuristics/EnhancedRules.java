package com.vtb.scanner.heuristics;

import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Расширенные правила обнаружения - МАКСИМАЛЬНОЕ ПОКРЫТИЕ
 * 
 * На основе:
 * - OWASP API Security Top 10 2023
 * - CWE Top 25
 * - SANS Top 25
 * - Реальные инциденты (Facebook, Uber, Capital One)
 */
public class EnhancedRules {
    
    // ═══════════════════════════════════════════════════════════════
    // BOLA / IDOR DETECTION (API1:2023)
    // ═══════════════════════════════════════════════════════════════
    
    // Все возможные варианты ID параметров
    private static final Pattern ID_PATTERNS = Pattern.compile(
        ".*(id|ID|Id|_id|_ID|identifier|uuid|UUID|guid|GUID|" +
        "userId|user_id|userID|user-id|" +
        "accountId|account_id|accountID|" +
        "customerId|customer_id|" +
        "orderId|order_id|" +
        "transactionId|transaction_id|tx_id|txId|" +
        "productId|product_id|" +
        "itemId|item_id|" +
        "documentId|document_id|doc_id|" +
        "fileId|file_id|" +
        "postId|post_id|" +
        "commentId|comment_id|" +
        "sessionId|session_id|" +
        "tokenId|token_id|" +
        "deviceId|device_id|" +
        "resourceId|resource_id|" +
        "entityId|entity_id|" +
        "objectId|object_id|" +
        "recordId|record_id|" +
        "key|Key|KEY).*",
        Pattern.CASE_INSENSITIVE
    );
    
    // ═══════════════════════════════════════════════════════════════
    // SQL INJECTION DETECTION
    // ═══════════════════════════════════════════════════════════════
    
    private static final Pattern SQL_PARAM_PATTERNS = Pattern.compile(
        ".*(query|Query|QUERY|sql|SQL|" +
        "search|Search|SEARCH|" +
        "filter|Filter|FILTER|" +
        "where|Where|WHERE|" +
        "orderBy|order_by|sort|Sort|" +
        "groupBy|group_by|" +
        "having|Having|" +
        "select|Select|" +
        "from|From|" +
        "table|Table|tableName|table_name|" +
        "column|Column|columnName|column_name|" +
        "field|Field|fieldName|field_name|" +
        "database|Database|db|DB|dbName|" +
        "condition|Condition|" +
        "criteria|Criteria).*",
        Pattern.CASE_INSENSITIVE
    );
    
    // ═══════════════════════════════════════════════════════════════
    // COMMAND INJECTION DETECTION
    // ═══════════════════════════════════════════════════════════════
    
    private static final Pattern CMD_PARAM_PATTERNS = Pattern.compile(
        ".*(command|cmd|CMD|exec|execute|" +
        "run|Run|shell|Shell|bash|" +
        "script|Script|" +
        "process|Process|" +
        "system|System|" +
        "call|Call|" +
        "invoke|Invoke).*",
        Pattern.CASE_INSENSITIVE
    );
    
    // ═══════════════════════════════════════════════════════════════
    // SSRF DETECTION (API7:2023)
    // ═══════════════════════════════════════════════════════════════
    
    private static final Pattern SSRF_PARAM_PATTERNS = Pattern.compile(
        ".*(url|URL|Url|uri|URI|Uri|" +
        "link|Link|href|Href|" +
        "redirect|Redirect|redirect_uri|" +
        "callback|Callback|callback_url|callbackUrl|" +
        "webhook|Webhook|webhook_url|webhookUrl|" +
        "proxy|Proxy|proxy_url|" +
        "fetch|Fetch|fetch_url|" +
        "download|Download|download_url|" +
        "import|Import|import_url|" +
        "source|Source|source_url|src|" +
        "target|Target|target_url|" +
        "destination|Destination|dest|" +
        "endpoint|Endpoint|api_url|apiUrl).*",
        Pattern.CASE_INSENSITIVE
    );
    
    // ═══════════════════════════════════════════════════════════════
    // ПЕРСОНАЛЬНЫЕ ДАННЫЕ (ФЗ-152)
    // ═══════════════════════════════════════════════════════════════
    
    private static final Set<String> PERSONAL_DATA_FIELDS = Set.of(
        // ФИО
        "name", "Name", "fullName", "full_name", "fullname",
        "firstName", "first_name", "lastname", "lastName", "last_name",
        "surname", "Surname", "middleName", "middle_name",
        "фио", "имя", "фамилия", "отчество",
        
        // Документы
        "passport", "Passport", "паспорт", "Паспорт",
        "inn", "INN", "ИНН", "инн",
        "snils", "SNILS", "СНИЛС", "снилс",
        "ogrnip", "OGRNIP", "ОГРНИП",
        
        // Контакты
        "email", "Email", "mail", "e-mail",
        "phone", "Phone", "telephone", "mobile",
        "телефон", "почта",
        
        // Адрес
        "address", "Address", "адрес", "Адрес",
        "location", "Location", "geo",
        
        // Даты
        "birthDate", "birth_date", "birthday", "dateOfBirth",
        "дата_рождения", "birthplace",
        
        // Медицинские
        "diagnosis", "Diagnosis", "диагноз",
        "medication", "лекарство", "treatment",
        "medicalRecord", "medical_record",
        
        // Финансовые
        "salary", "income", "зарплата",
        "bankAccount", "bank_account", "счет",
        "card", "cardNumber", "card_number", "карта"
    );
    
    // ═══════════════════════════════════════════════════════════════
    // ЧУВСТВИТЕЛЬНЫЕ ПОЛЯ (не должны быть в ответах)
    // ═══════════════════════════════════════════════════════════════
    
    private static final Set<String> SENSITIVE_FIELDS = Set.of(
        "password", "Password", "pwd", "passwd",
        "token", "Token", "accessToken", "access_token",
        "refreshToken", "refresh_token",
        "secret", "Secret", "secretKey", "secret_key",
        "apiKey", "api_key", "apikey", "API_KEY",
        "privateKey", "private_key", "privatekeyinPrivateKey",
        "hash", "Hash", "passwordHash", "password_hash",
        "salt", "Salt",
        "session", "Session", "sessionId", "session_id",
        "jwt", "JWT",
        "bearer", "Bearer",
        "otp", "OTP",
        "pin", "PIN",
        "cvv", "CVV", "cvc",
        "ssn", "SSN",
        "credit_card", "creditCard", "creditcard"
    );
    
    // ═══════════════════════════════════════════════════════════════
    // РОССИЙСКИЕ ПЛАТЕЖНЫЕ СИСТЕМЫ
    // ═══════════════════════════════════════════════════════════════
    
    private static final Pattern RUSSIAN_PAYMENT_PATTERNS = Pattern.compile(
        ".*(sbp|SBP|СБП|sberpay|sber|Sber|" +
        "mir|MIR|МИР|mirpay|" +
        "qiwi|QIWI|КИВИ|" +
        "yoomoney|yandex_money|яндекс.*деньги|" +
        "webmoney|WebMoney|" +
        "rubles|rub|RUB|рубл|₽).*",
        Pattern.CASE_INSENSITIVE
    );
    
    // ═══════════════════════════════════════════════════════════════
    // КРИПТОВАЛЮТЫ И BLOCKCHAIN
    // ═══════════════════════════════════════════════════════════════
    
    private static final Pattern CRYPTO_PATTERNS = Pattern.compile(
        ".*(wallet|Wallet|WALLET|" +
        "crypto|Crypto|cryptocurrency|" +
        "bitcoin|btc|BTC|" +
        "ethereum|eth|ETH|" +
        "blockchain|Blockchain|" +
        "transaction_hash|txHash|tx_hash|" +
        "privateKey|private_key|seed|mnemonic|" +
        "address|Address|wallet_address).*",
        Pattern.CASE_INSENSITIVE
    );
    
    // ═══════════════════════════════════════════════════════════════
    // PATH TRAVERSAL / LFI
    // ═══════════════════════════════════════════════════════════════
    
    private static final Pattern PATH_TRAVERSAL_PATTERNS = Pattern.compile(
        ".*(file|File|FILE|filename|fileName|file_name|" +
        "path|Path|PATH|filepath|filePath|file_path|" +
        "directory|Directory|dir|DIR|folder|" +
        "resource|Resource|include|Include|" +
        "template|Template|view|View).*",
        Pattern.CASE_INSENSITIVE
    );
    
    // ═══════════════════════════════════════════════════════════════
    // MASS ASSIGNMENT
    // ═══════════════════════════════════════════════════════════════
    
    private static final Set<String> DANGEROUS_FIELDS = Set.of(
        "role", "Role", "isAdmin", "is_admin", "admin",
        "permissions", "Permissions", "privileges",
        "status", "Status", "active", "Active", "enabled",
        "verified", "Verified", "confirmed",
        "balance", "Balance", "amount", "Amount",
        "price", "Price", "cost", "Cost"
    );
    
    // ═══════════════════════════════════════════════════════════════
    // GRAPHQL SPECIFIC
    // ═══════════════════════════════════════════════════════════════
    
    private static final Pattern GRAPHQL_PATTERNS = Pattern.compile(
        ".*(query|Query|mutation|Mutation|" +
        "subscription|Subscription|" +
        "introspection|__schema|__type).*",
        Pattern.CASE_INSENSITIVE
    );
    
    // ═══════════════════════════════════════════════════════════════
    // XXE / XML INJECTION
    // ═══════════════════════════════════════════════════════════════
    
    private static final Pattern XML_PATTERNS = Pattern.compile(
        ".*(xml|XML|soap|SOAP|wsdl|WSDL|" +
        "entity|Entity|dtd|DTD|" +
        "external|External).*",
        Pattern.CASE_INSENSITIVE
    );
    
    // ═══════════════════════════════════════════════════════════════
    // NOSQL INJECTION
    // ═══════════════════════════════════════════════════════════════
    
    private static final Pattern NOSQL_PATTERNS = Pattern.compile(
        ".*(mongo|MongoDB|" +
        "\\$where|\\$regex|\\$gt|\\$lt|\\$ne|" +
        "aggregate|Aggregate|pipeline).*",
        Pattern.CASE_INSENSITIVE
    );
    
    // ═══════════════════════════════════════════════════════════════
    // REGEX DOS (ReDoS)
    // ═══════════════════════════════════════════════════════════════
    
    private static final Pattern REGEX_PATTERNS = Pattern.compile(
        ".*(regex|Regex|REGEX|pattern|Pattern|" +
        "regexp|RegExp|match|Match|" +
        "expression|Expression).*",
        Pattern.CASE_INSENSITIVE
    );
    
    // ═══════════════════════════════════════════════════════════════
    // OPEN BANKING / PSD2
    // ═══════════════════════════════════════════════════════════════
    
    private static final Pattern OPEN_BANKING_PATTERNS = Pattern.compile(
        ".*(psd2|PSD2|openbanking|open_banking|" +
        "aisp|AISP|pisp|PISP|" +
        "consent|Consent|authorization|Authorization|" +
        "account.*access|payment.*initiation).*",
        Pattern.CASE_INSENSITIVE
    );
    
    // ═══════════════════════════════════════════════════════════════
    // IOT / DEVICE MANAGEMENT
    // ═══════════════════════════════════════════════════════════════
    
    private static final Pattern IOT_PATTERNS = Pattern.compile(
        ".*(device|Device|DEVICE|deviceId|device_id|" +
        "sensor|Sensor|actuator|Actuator|" +
        "mqtt|MQTT|coap|CoAP|" +
        "firmware|Firmware|update|Update|" +
        "provision|Provision|register|Register).*",
        Pattern.CASE_INSENSITIVE
    );
    
    // ═══════════════════════════════════════════════════════════════
    // TEMPLATE INJECTION (SSTI)
    // ═══════════════════════════════════════════════════════════════
    
    private static final Pattern TEMPLATE_PATTERNS = Pattern.compile(
        ".*(template|Template|render|Render|" +
        "jinja|Jinja|twig|Twig|" +
        "freemarker|FreeMarker|velocity|Velocity|" +
        "expression|Expression|el|EL).*",
        Pattern.CASE_INSENSITIVE
    );
    
    // ═══════════════════════════════════════════════════════════════
    // LDAP INJECTION
    // ═══════════════════════════════════════════════════════════════
    
    private static final Pattern LDAP_CORE_PATTERNS = Pattern.compile(
        ".*(ldap|distinguished\\s*name|directory|bind|authenticate).*",
        Pattern.CASE_INSENSITIVE
    );

    private static final Set<String> LDAP_SEGMENTS = Set.of("dn", "cn", "ou", "dc");
    
    // ═══════════════════════════════════════════════════════════════
    // DESERIALIZATION
    // ═══════════════════════════════════════════════════════════════
    
    private static final Set<String> DESERIALIZATION_MARKERS = Set.of(
        "serialize", "deserializ", "pickle", "unmarshal",
        "objectinput", "objectstream", "__class__", "__type__", "serialized"
    );
    
    // ═══════════════════════════════════════════════════════════════
    // JWT SPECIFIC
    // ═══════════════════════════════════════════════════════════════
    
    private static final Set<String> JWT_DANGEROUS_CLAIMS = Set.of(
        "alg", "typ", "kid", "jku", "x5u", "x5c",
        "role", "roles", "permissions", "scope",
        "admin", "isAdmin", "is_admin"
    );
    
    // ═══════════════════════════════════════════════════════════════
    // МЕТОДЫ ПРОВЕРКИ
    // ═══════════════════════════════════════════════════════════════
    
    /**
     * Проверка параметра на SQL Injection риск
     */
    public static boolean isSQLInjectionRisk(Parameter param) {
        if (param == null || param.getName() == null) return false;
        
        // 1. Проверка имени
        if (SQL_PARAM_PATTERNS.matcher(param.getName()).matches()) {
            String paramNameLower = param.getName().toLowerCase(Locale.ROOT);
            if (isLikelySafeSqlParam(paramNameLower)) {
                return false;
            }

            // 2. Проверка валидации
            if (param.getSchema() == null) return true;
            
            Schema schema = param.getSchema();
            String format = schema.getFormat() != null ? schema.getFormat().toLowerCase(Locale.ROOT) : null;
            String type = schema.getType() != null ? schema.getType().toLowerCase(Locale.ROOT) : null;

            boolean hasValidation =
                (schema.getPattern() != null && !schema.getPattern().isEmpty()) ||
                (schema.getEnum() != null && !schema.getEnum().isEmpty()) ||
                (schema.getMaxLength() != null && schema.getMaxLength() < 100) ||
                (schema.getMinLength() != null && schema.getMinLength() > 0) ||
                "uuid".equals(format) ||
                "date".equals(format) ||
                "date-time".equals(format) ||
                "time".equals(format) ||
                "integer".equals(type) ||
                "number".equals(type) ||
                schema.getMinimum() != null ||
                schema.getMaximum() != null;
            
            return !hasValidation; // Риск если НЕТ валидации
        }
        
        return false;
    }

    private static boolean isLikelySafeSqlParam(String paramNameLower) {
        if (paramNameLower.contains("date") || paramNameLower.contains("time")) {
            return true;
        }
        if (paramNameLower.contains("consent") || paramNameLower.contains("token")) {
            return true;
        }
        if (paramNameLower.contains("amount") || paramNameLower.contains("balance")) {
            return true;
        }
        if (paramNameLower.endsWith("_id") || paramNameLower.endsWith("id")) {
            return true;
        }
        return false;
    }
    
    /**
     * Проверка на Command Injection
     */
    public static boolean isCommandInjectionRisk(Parameter param) {
        if (param == null || param.getName() == null) return false;
        return CMD_PARAM_PATTERNS.matcher(param.getName()).matches();
    }
    
    /**
     * Проверка на SSRF
     */
    public static boolean isSSRFRisk(Parameter param) {
        if (param == null || param.getName() == null) return false;
        return SSRF_PARAM_PATTERNS.matcher(param.getName()).matches();
    }
    
    /**
     * Проверка на ID параметр (BOLA риск)
     */
    public static boolean isIDParameter(String name) {
        if (name == null) return false;
        return ID_PATTERNS.matcher(name).matches();
    }
    
    /**
     * Проверка на персональные данные (ФЗ-152)
     */
    public static boolean hasPersonalData(Schema schema) {
        if (schema == null || schema.getProperties() == null) return false;
        
        @SuppressWarnings("rawtypes")
        Map properties = schema.getProperties();
        
        for (Object key : properties.keySet()) {
            String fieldName = key.toString();
            if (PERSONAL_DATA_FIELDS.contains(fieldName) ||
                PERSONAL_DATA_FIELDS.stream().anyMatch(pd -> 
                    fieldName.toLowerCase().contains(pd.toLowerCase()))) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Проверка на чувствительные поля в ответе
     */
    public static List<String> findSensitiveFieldsInResponse(Schema schema) {
        List<String> found = new ArrayList<>();
        
        if (schema == null || schema.getProperties() == null) return found;
        
        @SuppressWarnings("rawtypes")
        Map properties = schema.getProperties();
        
        for (Object key : properties.keySet()) {
            String fieldName = key.toString();
            if (SENSITIVE_FIELDS.contains(fieldName) ||
                SENSITIVE_FIELDS.stream().anyMatch(sf -> 
                    fieldName.toLowerCase().contains(sf.toLowerCase()))) {
                found.add(fieldName);
            }
        }
        
        return found;
    }
    
    /**
     * Проверка на чувствительные данные в URL параметре
     * Пароли, токены, секреты не должны передаваться в query string
     */
    public static boolean isSensitiveDataInURL(Parameter param) {
        if (param == null || param.getName() == null || !"query".equals(param.getIn())) {
            return false;
        }
        
        String lowerName = param.getName().toLowerCase();
        return SENSITIVE_FIELDS.stream()
            .anyMatch(sf -> lowerName.contains(sf.toLowerCase()));
    }
    
    /**
     * Проверка description на упоминания SQL/query
     */
    public static boolean mentionsSQLInDescription(String description) {
        if (description == null) return false;
        String descLower = description.toLowerCase();
        return descLower.contains("query") || descLower.contains("sql") ||
               descLower.contains("database") || descLower.contains("db");
    }
    
    /**
     * Оценка качества валидации (0-100)
     */
    public static int scoreValidation(Parameter param) {
        if (param == null || param.getSchema() == null) return 0;
        
        Schema schema = param.getSchema();
        int score = 0;
        
        if (schema.getPattern() != null) score += 40; // Regex validation
        if (schema.getEnum() != null && !schema.getEnum().isEmpty()) score += 50; // Whitelist
        if (schema.getFormat() != null) score += 20; // Type validation
        if (schema.getMaxLength() != null && schema.getMaxLength() < 100) score += 15;
        if (schema.getMinLength() != null && schema.getMinLength() > 0) score += 10;
        if (schema.getMinimum() != null || schema.getMaximum() != null) score += 10;
        
        return Math.min(100, score);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // НОВЫЕ МЕТОДЫ ПРОВЕРКИ (14 паттернов)
    // ═══════════════════════════════════════════════════════════════
    
    public static boolean isRussianPaymentRisk(Parameter param) {
        if (param == null || param.getName() == null) return false;
        return RUSSIAN_PAYMENT_PATTERNS.matcher(param.getName()).matches();
    }
    
    public static boolean isCryptoRisk(Parameter param) {
        if (param == null || param.getName() == null) return false;
        return CRYPTO_PATTERNS.matcher(param.getName()).matches();
    }
    
    public static boolean isPathTraversalRisk(Parameter param) {
        if (param == null || param.getName() == null) return false;
        String name = param.getName().toLowerCase(Locale.ROOT);
        if (name.equals("page") || name.equals("page_size") || name.equals("pagesize")) {
            return false;
        }
        return PATH_TRAVERSAL_PATTERNS.matcher(param.getName()).matches();
    }
    
    public static boolean hasDangerousFields(Schema schema) {
        return !findMassAssignmentRiskFields(schema, null, null).isEmpty();
    }
    
    /**
     * Расширенный анализ полей, которые могут дать Mass Assignment.
     * Возвращает конкретные поля, требующие ручной проверки (учитывает контекст).
     */
    public static List<String> findMassAssignmentRiskFields(Schema schema, Operation operation, String path) {
        List<String> result = new ArrayList<>();
        if (schema == null || schema.getProperties() == null) {
            return result;
        }

        String lowerPath = path != null ? path.toLowerCase(Locale.ROOT) : "";
        String text = "";
        if (operation != null) {
            StringBuilder builder = new StringBuilder();
            if (operation.getSummary() != null) {
                builder.append(operation.getSummary()).append(' ');
            }
            if (operation.getDescription() != null) {
                builder.append(operation.getDescription());
            }
            text = builder.toString().toLowerCase(Locale.ROOT);
        }

        @SuppressWarnings("rawtypes")
        Map properties = schema.getProperties();
        for (Object key : properties.keySet()) {
            if (key == null) {
                continue;
            }
            String fieldName = key.toString();
            String lowerField = fieldName.toLowerCase(Locale.ROOT);
            @SuppressWarnings("rawtypes")
            Schema propertySchema = (Schema) properties.get(key);

            if (!isDangerousFieldName(lowerField)) {
                continue;
            }
            if (propertySchema != null && Boolean.TRUE.equals(propertySchema.getReadOnly())) {
                continue;
            }
            if (isBusinessAllowedContext(lowerField, lowerPath, text)) {
                continue;
            }
            if (isStronglyValidated(propertySchema)) {
                continue;
            }

            result.add(fieldName);
        }

        return result;
    }

    private static boolean isDangerousFieldName(String lowerField) {
        if (DANGEROUS_FIELDS.contains(lowerField)) {
            return true;
        }
        // Авторы могут использовать CAMEL CASE/UPPER CASE
        for (String candidate : DANGEROUS_FIELDS) {
            if (candidate.equalsIgnoreCase(lowerField)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isBusinessAllowedContext(String lowerField, String lowerPath, String text) {
        if ("permissions".equals(lowerField) || "privileges".equals(lowerField) || lowerField.contains("scope")) {
            return lowerPath.contains("consent") || lowerPath.contains("permission") ||
                   text.contains("consent") || text.contains("open banking") || text.contains("scope");
        }
        if ("amount".equals(lowerField) || "balance".equals(lowerField) || "price".equals(lowerField) || "cost".equals(lowerField)) {
            return lowerPath.contains("payment") || lowerPath.contains("transfer") ||
                   lowerPath.contains("agreement") || lowerPath.contains("order") ||
                   text.contains("payment") || text.contains("transfer") || text.contains("transaction");
        }
        if ("status".equals(lowerField)) {
            return lowerPath.endsWith("/status") || text.contains("status update");
        }
        return false;
    }

    private static boolean isStronglyValidated(Schema<?> propertySchema) {
        if (propertySchema == null) {
            return false;
        }

        if (propertySchema.getEnum() != null && !propertySchema.getEnum().isEmpty()) {
            return true;
        }
        if (propertySchema.getPattern() != null && !propertySchema.getPattern().isEmpty()) {
            return true;
        }
        if (propertySchema.getMaximum() != null || propertySchema.getMinimum() != null) {
            return true;
        }
        if (propertySchema.getItems() != null) {
            Schema<?> items = propertySchema.getItems();
            if (items != null && items.getEnum() != null && !items.getEnum().isEmpty()) {
                return true;
            }
        }
        return false;
    }
    
    public static boolean isGraphQLRisk(Parameter param) {
        if (param == null || param.getName() == null) return false;
        return GRAPHQL_PATTERNS.matcher(param.getName()).matches();
    }
    
    public static boolean isXMLRisk(Parameter param) {
        if (param == null || param.getName() == null) return false;
        return XML_PATTERNS.matcher(param.getName()).matches();
    }
    
    public static boolean isNoSQLRisk(Parameter param) {
        if (param == null || param.getName() == null) return false;
        return NOSQL_PATTERNS.matcher(param.getName()).matches();
    }
    
    public static boolean isReDoSRisk(Parameter param) {
        if (param == null || param.getName() == null) return false;
        return REGEX_PATTERNS.matcher(param.getName()).matches();
    }
    
    public static boolean isOpenBankingRisk(Parameter param) {
        if (param == null || param.getName() == null) return false;
        return OPEN_BANKING_PATTERNS.matcher(param.getName()).matches();
    }
    
    public static boolean isIoTRisk(Parameter param) {
        if (param == null || param.getName() == null) return false;
        return IOT_PATTERNS.matcher(param.getName()).matches();
    }
    
    public static boolean isTemplateInjectionRisk(Parameter param) {
        if (param == null || param.getName() == null) return false;
        return TEMPLATE_PATTERNS.matcher(param.getName()).matches();
    }
    
    public static boolean isLDAPRisk(Parameter param) {
        if (param == null || param.getName() == null) return false;

        String name = param.getName().toLowerCase(Locale.ROOT);

        if ((name.endsWith("_id") || name.endsWith("id")) && name.length() > 3) {
            return false;
        }

        if (LDAP_CORE_PATTERNS.matcher(name).matches()) {
            return true;
        }

        String normalized = name.replace('-', '_');
        for (String segment : LDAP_SEGMENTS) {
            if (normalized.equals(segment) ||
                normalized.endsWith("_" + segment) ||
                normalized.startsWith(segment + "_")) {
                return true;
            }
        }

        return false;
    }
    
    public static boolean isDeserializationRisk(Parameter param) {
        if (param == null || param.getName() == null) {
            return false;
        }

        String lower = param.getName().toLowerCase(Locale.ROOT);
        boolean markerFound = DESERIALIZATION_MARKERS.stream().anyMatch(lower::contains);
        if (!markerFound) {
            return false;
        }

        Schema<?> schema = param.getSchema();
        if (schema != null) {
            if (schema.getEnum() != null && !schema.getEnum().isEmpty()) {
                return false;
            }
            if ("string".equals(schema.getType()) && "date-time".equals(schema.getFormat())) {
                return false;
            }
        }

        return true;
    }
    
    public static List<String> findDangerousJWTClaims(Schema schema) {
        List<String> found = new ArrayList<>();
        
        if (schema == null || schema.getProperties() == null) return found;
        
        @SuppressWarnings("rawtypes")
        Map properties = schema.getProperties();
        
        for (Object key : properties.keySet()) {
            String fieldName = key.toString();
            if (JWT_DANGEROUS_CLAIMS.contains(fieldName)) {
                found.add(fieldName);
            }
        }
        
        return found;
    }
}

