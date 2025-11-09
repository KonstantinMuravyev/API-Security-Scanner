package com.vtb.scanner.integration;

import com.vtb.scanner.scanners.*;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Paths;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.QueryParameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration тесты для НОВЫХ паттернов
 * 
 * Проверяют что сканеры РЕАЛЬНО находят уязвимости на синтетических API
 */
class NewPatternsIntegrationTest {
    
    /**
     * Тест: AuthScanner находит Crypto параметр
     */
    @Test
    void testAuthScanner_FindsCryptoRisk() {
        OpenAPI api = createAPIWithCryptoParam();
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.setOpenAPI(api);
        
        AuthScanner scanner = new AuthScanner("http://test.com");
        List<com.vtb.scanner.models.Vulnerability> vulns = scanner.scan(api, parser);
        
        // ДОЛЖНА быть найдена крипто уязвимость!
        com.vtb.scanner.models.Vulnerability crypto = vulns.stream()
            .filter(v -> v.getId().startsWith("AUTH-") && 
                        v.getType() == com.vtb.scanner.models.VulnerabilityType.BROKEN_AUTHENTICATION &&
                        (v.getDescription().contains("крипт") || v.getDescription().contains("crypto") || 
                         v.getTitle().contains("Крипт")))
            .findFirst()
            .orElse(null);
        
        assertNotNull(crypto, "Crypto уязвимость НЕ НАЙДЕНА!");
        assertEquals(com.vtb.scanner.models.VulnerabilityType.BROKEN_AUTHENTICATION, crypto.getType());
        assertEquals(com.vtb.scanner.models.Severity.CRITICAL, crypto.getSeverity());
        assertTrue(crypto.getConfidence() > 50, 
            "Confidence должен быть > 50, получено: " + crypto.getConfidence());
    }
    
    /**
     * Тест: AuthScanner находит Russian Payment параметр
     */
    @Test
    void testAuthScanner_FindsRussianPaymentRisk() {
        OpenAPI api = createAPIWithRussianPayment();
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.setOpenAPI(api);
        
        AuthScanner scanner = new AuthScanner("http://test.com");
        List<com.vtb.scanner.models.Vulnerability> vulns = scanner.scan(api, parser);
        
        com.vtb.scanner.models.Vulnerability ruPay = vulns.stream()
            .filter(v -> v.getId().startsWith("AUTH-") &&
                        v.getType() == com.vtb.scanner.models.VulnerabilityType.BROKEN_AUTHENTICATION &&
                        (v.getDescription().contains("СБП") || v.getDescription().contains("российск") ||
                         v.getTitle().contains("Российск")))
            .findFirst()
            .orElse(null);
        
        assertNotNull(ruPay, "Russian Payment уязвимость НЕ НАЙДЕНА!");
        assertTrue(ruPay.getDescription().contains("СБП") || 
                   ruPay.getDescription().contains("российск"),
            "Описание должно упоминать российские платежи");
    }
    
    /**
     * Тест: AuthScanner находит JWT Claims
     */
    @Test
    void testAuthScanner_FindsJWTClaims() {
        OpenAPI api = createAPIWithJWTClaims();
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.setOpenAPI(api);
        
        AuthScanner scanner = new AuthScanner("http://test.com");
        List<com.vtb.scanner.models.Vulnerability> vulns = scanner.scan(api, parser);
        
        com.vtb.scanner.models.Vulnerability jwt = vulns.stream()
            .filter(v -> (v.getId().startsWith("AUTH-") || v.getId().startsWith("WEAK-")) &&
                        (v.getType() == com.vtb.scanner.models.VulnerabilityType.WEAK_AUTHENTICATION ||
                         v.getType() == com.vtb.scanner.models.VulnerabilityType.BROKEN_AUTHENTICATION) &&
                        (v.getDescription().contains("JWT") || v.getDescription().contains("claims") ||
                         v.getTitle().contains("JWT")))
            .findFirst()
            .orElse(null);
        
        assertNotNull(jwt, "JWT Claims уязвимость НЕ НАЙДЕНА!");
        assertTrue(jwt.getDescription().contains("alg") || 
                   jwt.getDescription().contains("role"),
            "Должно упоминать опасные claims");
    }
    
    /**
     * Тест: InjectionScanner находит NoSQL injection
     */
    @Test
    void testInjectionScanner_FindsNoSQL() {
        OpenAPI api = createAPIWithNoSQLParam();
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.setOpenAPI(api);
        
        InjectionScanner scanner = new InjectionScanner("http://test.com");
        List<com.vtb.scanner.models.Vulnerability> vulns = scanner.scan(api, parser);
        
        com.vtb.scanner.models.Vulnerability nosql = vulns.stream()
            .filter(v -> v.getType() == com.vtb.scanner.models.VulnerabilityType.NOSQL_INJECTION)
            .findFirst()
            .orElse(null);
        
        assertNotNull(nosql, "NoSQL Injection НЕ НАЙДЕНА!");
        assertTrue(nosql.getDescription().contains("MongoDB") || 
                   nosql.getDescription().contains("$where"),
            "Описание должно упоминать MongoDB атаки");
    }
    
    /**
     * Тест: InjectionScanner находит LDAP injection
     */
    @Test
    void testInjectionScanner_FindsLDAP() {
        OpenAPI api = createAPIWithLDAPParam();
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.setOpenAPI(api);
        
        InjectionScanner scanner = new InjectionScanner("http://test.com");
        List<com.vtb.scanner.models.Vulnerability> vulns = scanner.scan(api, parser);
        
        com.vtb.scanner.models.Vulnerability ldap = vulns.stream()
            .filter(v -> v.getType() == com.vtb.scanner.models.VulnerabilityType.LDAP_INJECTION)
            .findFirst()
            .orElse(null);
        
        assertNotNull(ldap, "LDAP Injection НЕ НАЙДЕНА!");
    }
    
    /**
     * Тест: InjectionScanner находит SSTI
     */
    @Test
    void testInjectionScanner_FindsTemplateInjection() {
        OpenAPI api = createAPIWithTemplateParam();
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.setOpenAPI(api);
        
        InjectionScanner scanner = new InjectionScanner("http://test.com");
        List<com.vtb.scanner.models.Vulnerability> vulns = scanner.scan(api, parser);
        
        com.vtb.scanner.models.Vulnerability ssti = vulns.stream()
            .filter(v -> v.getId().startsWith("CMD-") &&
                        v.getType() == com.vtb.scanner.models.VulnerabilityType.COMMAND_INJECTION &&
                        (v.getDescription().contains("template") || v.getDescription().contains("SSTI") ||
                         v.getTitle().contains("Template")))
            .findFirst()
            .orElse(null);
        
        assertNotNull(ssti, "SSTI уязвимость НЕ НАЙДЕНА!");
        assertEquals(com.vtb.scanner.models.Severity.CRITICAL, ssti.getSeverity(),
            "SSTI должна быть CRITICAL!");
        assertTrue(ssti.getDescription().contains("RCE"),
            "SSTI описание должно упоминать RCE");
    }
    
    /**
     * Тест: InjectionScanner находит XXE
     */
    @Test
    void testInjectionScanner_FindsXXE() {
        OpenAPI api = createAPIWithXMLParam();
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.setOpenAPI(api);
        
        InjectionScanner scanner = new InjectionScanner("http://test.com");
        List<com.vtb.scanner.models.Vulnerability> vulns = scanner.scan(api, parser);
        
        com.vtb.scanner.models.Vulnerability xxe = vulns.stream()
            .filter(v -> (v.getId().startsWith("CMD-") || v.getId().startsWith("SSRF-")) &&
                        (v.getDescription().contains("XXE") || v.getDescription().contains("XML") ||
                         v.getTitle().contains("XXE") || v.getTitle().contains("XML")))
            .findFirst()
            .orElse(null);
        
        assertNotNull(xxe, "XXE уязвимость НЕ НАЙДЕНА!");
    }
    
    /**
     * Тест: InjectionScanner находит Deserialization
     */
    @Test
    void testInjectionScanner_FindsDeserialization() {
        OpenAPI api = createAPIWithDeserializationParam();
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.setOpenAPI(api);
        
        InjectionScanner scanner = new InjectionScanner("http://test.com");
        List<com.vtb.scanner.models.Vulnerability> vulns = scanner.scan(api, parser);
        
        com.vtb.scanner.models.Vulnerability deser = vulns.stream()
            .filter(v -> v.getId().startsWith("CMD-") &&
                        (v.getDescription().contains("deserial") || v.getDescription().contains("unserialize") ||
                         v.getTitle().contains("Deserial") || v.getTitle().contains("Десериализац")))
            .findFirst()
            .orElse(null);
        
        assertNotNull(deser, "Deserialization уязвимость НЕ НАЙДЕНА!");
        assertEquals(com.vtb.scanner.models.Severity.CRITICAL, deser.getSeverity(),
            "Deserialization должна быть CRITICAL!");
        assertTrue(deser.getConfidence() > 70,
            "Confidence для Deserialization должен быть высоким");
    }
    
    /**
     * Тест: ResourceScanner находит Path Traversal
     */
    @Test
    void testResourceScanner_FindsPathTraversal() {
        OpenAPI api = createAPIWithFileParam();
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.setOpenAPI(api);
        
        ResourceScanner scanner = new ResourceScanner("http://test.com");
        List<com.vtb.scanner.models.Vulnerability> vulns = scanner.scan(api, parser);
        
        com.vtb.scanner.models.Vulnerability pathTraversal = vulns.stream()
            .filter(v -> (v.getId().startsWith("SSRF-") || v.getId().startsWith("RES-")) &&
                        (v.getDescription().contains("path traversal") || v.getDescription().contains("../../") ||
                         v.getTitle().contains("Path Traversal") || v.getTitle().contains("путь")))
            .findFirst()
            .orElse(null);
        
        assertNotNull(pathTraversal, "Path Traversal уязвимость НЕ НАЙДЕНА!");
        assertTrue(pathTraversal.getDescription().contains("../../"),
            "Описание должно упоминать path traversal атаки");
    }
    
    /**
     * Тест: ResourceScanner находит ReDoS
     */
    @Test
    void testResourceScanner_FindsReDoS() {
        OpenAPI api = createAPIWithRegexParam();
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.setOpenAPI(api);
        
        ResourceScanner scanner = new ResourceScanner("http://test.com");
        List<com.vtb.scanner.models.Vulnerability> vulns = scanner.scan(api, parser);
        
        com.vtb.scanner.models.Vulnerability redos = vulns.stream()
            .filter(v -> (v.getId().startsWith("RES-") || v.getId().startsWith("RATE-")) &&
                        (v.getDescription().contains("regex") || v.getDescription().contains("ReDoS") ||
                         v.getDescription().contains("backtracking") || v.getTitle().contains("ReDoS")))
            .findFirst()
            .orElse(null);
        
        assertNotNull(redos, "ReDoS уязвимость НЕ НАЙДЕНА!");
        assertTrue(redos.getDescription().contains("backtracking") ||
                   redos.getDescription().contains("DoS"),
            "Описание должно упоминать DoS через regex");
    }
    
    /**
     * Тест: MisconfigScanner находит GraphQL проблемы
     */
    @Test
    void testMisconfigScanner_FindsGraphQL() {
        OpenAPI api = createAPIWithGraphQL();
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.setOpenAPI(api);
        
        MisconfigScanner scanner = new MisconfigScanner("http://test.com");
        List<com.vtb.scanner.models.Vulnerability> vulns = scanner.scan(api, parser);
        
        com.vtb.scanner.models.Vulnerability graphql = vulns.stream()
            .filter(v -> v.getId().startsWith("MISC-") &&
                        v.getType() == com.vtb.scanner.models.VulnerabilityType.SECURITY_MISCONFIGURATION &&
                        (v.getDescription().contains("GraphQL") || v.getDescription().contains("graphql") ||
                         v.getTitle().contains("GraphQL")))
            .findFirst()
            .orElse(null);
        
        assertNotNull(graphql, "GraphQL уязвимость НЕ НАЙДЕНА!");
        assertTrue(graphql.getDescription().contains("introspection") ||
                   graphql.getDescription().contains("depth"),
            "Описание должно упоминать GraphQL специфичные атаки");
    }
    
    /**
     * Тест: MisconfigScanner находит IoT проблемы
     */
    @Test
    void testMisconfigScanner_FindsIoT() {
        OpenAPI api = createAPIWithIoTParam();
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.setOpenAPI(api);
        
        MisconfigScanner scanner = new MisconfigScanner("http://test.com");
        List<com.vtb.scanner.models.Vulnerability> vulns = scanner.scan(api, parser);
        
        com.vtb.scanner.models.Vulnerability iot = vulns.stream()
            .filter(v -> v.getId().startsWith("MISC-") &&
                        v.getType() == com.vtb.scanner.models.VulnerabilityType.SECURITY_MISCONFIGURATION &&
                        (v.getDescription().contains("IoT") || v.getDescription().contains("device") ||
                         v.getDescription().contains("firmware") || v.getTitle().contains("IoT")))
            .findFirst()
            .orElse(null);
        
        assertNotNull(iot, "IoT уязвимость НЕ НАЙДЕНА!");
        assertTrue(iot.getDescription().contains("firmware") ||
                   iot.getDescription().contains("device"),
            "Описание должно упоминать IoT атаки");
    }
    
    /**
     * Тест: MisconfigScanner находит Open Banking проблемы
     */
    @Test
    void testMisconfigScanner_FindsOpenBanking() {
        OpenAPI api = createAPIWithOpenBankingParam();
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.setOpenAPI(api);
        
        MisconfigScanner scanner = new MisconfigScanner("http://test.com");
        List<com.vtb.scanner.models.Vulnerability> vulns = scanner.scan(api, parser);
        
        com.vtb.scanner.models.Vulnerability psd2 = vulns.stream()
            .filter(v -> v.getId().startsWith("MISC-") &&
                        v.getType() == com.vtb.scanner.models.VulnerabilityType.SECURITY_MISCONFIGURATION &&
                        (v.getDescription().contains("PSD2") || v.getDescription().contains("SCA") ||
                         v.getDescription().contains("Open Banking") || v.getTitle().contains("PSD2")))
            .findFirst()
            .orElse(null);
        
        assertNotNull(psd2, "Open Banking/PSD2 уязвимость НЕ НАЙДЕНА!");
        assertTrue(psd2.getDescription().contains("PSD2") ||
                   psd2.getDescription().contains("SCA"),
            "Описание должно упоминать PSD2 требования");
    }
    
    /**
     * Тест: PropertyAuthScanner находит Mass Assignment
     */
    @Test
    void testPropertyAuthScanner_FindsMassAssignment() {
        OpenAPI api = createAPIWithDangerousFields();
        com.vtb.scanner.core.OpenAPIParser parser = new com.vtb.scanner.core.OpenAPIParser();
        parser.setOpenAPI(api);
        
        PropertyAuthScanner scanner = new PropertyAuthScanner("http://test.com");
        List<com.vtb.scanner.models.Vulnerability> vulns = scanner.scan(api, parser);
        
        com.vtb.scanner.models.Vulnerability massAssign = vulns.stream()
            .filter(v -> v.getId().startsWith("PROP-") &&
                        v.getType() == com.vtb.scanner.models.VulnerabilityType.BROKEN_OBJECT_PROPERTY &&
                        (v.getDescription().contains("mass assignment") || v.getDescription().contains("role") ||
                         v.getDescription().contains("admin") || v.getTitle().contains("Mass Assignment")))
            .findFirst()
            .orElse(null);
        
        assertNotNull(massAssign, "Mass Assignment уязвимость НЕ НАЙДЕНА!");
        assertTrue(massAssign.getDescription().contains("role") ||
                   massAssign.getDescription().contains("admin") ||
                   massAssign.getDescription().contains("balance"),
            "Описание должно упоминать опасные поля");
        assertTrue(massAssign.getConfidence() > 50,
            "Confidence для Mass Assignment должен быть > 50");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // HELPER METHODS - создание синтетических API для тестов
    // ═══════════════════════════════════════════════════════════════
    
    private OpenAPI createAPIWithCryptoParam() {
        OpenAPI api = new OpenAPI();
        api.setInfo(new Info().title("Test API"));
        
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        
        Operation operation = new Operation();
        io.swagger.v3.oas.models.parameters.Parameter param = new QueryParameter();
        param.setName("walletAddress");
        param.setSchema(new Schema().type("string"));
        operation.addParametersItem(param);
        
        pathItem.setPost(operation);
        paths.addPathItem("/crypto/send", pathItem);
        api.setPaths(paths);
        
        return api;
    }
    
    private OpenAPI createAPIWithRussianPayment() {
        OpenAPI api = new OpenAPI();
        api.setInfo(new Info().title("Test API"));
        
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        
        Operation operation = new Operation();
        io.swagger.v3.oas.models.parameters.Parameter param = new QueryParameter();
        param.setName("sbpPayment");
        param.setSchema(new Schema().type("string"));
        operation.addParametersItem(param);
        
        pathItem.setPost(operation);
        paths.addPathItem("/payment/sbp", pathItem);
        api.setPaths(paths);
        
        return api;
    }
    
    private OpenAPI createAPIWithJWTClaims() {
        OpenAPI api = new OpenAPI();
        api.setInfo(new Info().title("Test API"));
        
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        
        Operation operation = new Operation();
        
        // Request body с опасными JWT claims
        RequestBody requestBody = new RequestBody();
        Content content = new Content();
        MediaType mediaType = new MediaType();
        
        Schema schema = new Schema();
        Map<String, Schema> properties = new HashMap<>();
        properties.put("alg", new Schema().type("string"));
        properties.put("role", new Schema().type("string"));
        schema.setProperties(properties);
        
        mediaType.setSchema(schema);
        content.addMediaType("application/json", mediaType);
        requestBody.setContent(content);
        operation.setRequestBody(requestBody);
        
        pathItem.setPost(operation);
        paths.addPathItem("/auth/token", pathItem);
        api.setPaths(paths);
        
        return api;
    }
    
    private OpenAPI createAPIWithNoSQLParam() {
        OpenAPI api = new OpenAPI();
        api.setInfo(new Info().title("Test API"));
        
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        
        Operation operation = new Operation();
        io.swagger.v3.oas.models.parameters.Parameter param = new QueryParameter();
        param.setName("mongoQuery");
        param.setSchema(new Schema().type("string"));
        operation.addParametersItem(param);
        
        pathItem.setGet(operation);
        paths.addPathItem("/search", pathItem);
        api.setPaths(paths);
        
        return api;
    }
    
    private OpenAPI createAPIWithLDAPParam() {
        OpenAPI api = new OpenAPI();
        api.setInfo(new Info().title("Test API"));
        
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        
        Operation operation = new Operation();
        io.swagger.v3.oas.models.parameters.Parameter param = new QueryParameter();
        param.setName("ldapQuery");
        param.setSchema(new Schema().type("string"));
        operation.addParametersItem(param);
        
        pathItem.setGet(operation);
        paths.addPathItem("/users/search", pathItem);
        api.setPaths(paths);
        
        return api;
    }
    
    private OpenAPI createAPIWithTemplateParam() {
        OpenAPI api = new OpenAPI();
        api.setInfo(new Info().title("Test API"));
        
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        
        Operation operation = new Operation();
        io.swagger.v3.oas.models.parameters.Parameter param = new QueryParameter();
        param.setName("templateName");
        param.setSchema(new Schema().type("string"));
        operation.addParametersItem(param);
        
        pathItem.setPost(operation);
        paths.addPathItem("/render", pathItem);
        api.setPaths(paths);
        
        return api;
    }
    
    private OpenAPI createAPIWithXMLParam() {
        OpenAPI api = new OpenAPI();
        api.setInfo(new Info().title("Test API"));
        
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        
        Operation operation = new Operation();
        io.swagger.v3.oas.models.parameters.Parameter param = new QueryParameter();
        param.setName("xmlData");
        param.setSchema(new Schema().type("string"));
        operation.addParametersItem(param);
        
        pathItem.setPost(operation);
        paths.addPathItem("/soap/process", pathItem);
        api.setPaths(paths);
        
        return api;
    }
    
    private OpenAPI createAPIWithDeserializationParam() {
        OpenAPI api = new OpenAPI();
        api.setInfo(new Info().title("Test API"));
        
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        
        Operation operation = new Operation();
        io.swagger.v3.oas.models.parameters.Parameter param = new QueryParameter();
        param.setName("serializedObject");
        param.setSchema(new Schema().type("string"));
        operation.addParametersItem(param);
        
        pathItem.setPost(operation);
        paths.addPathItem("/data/load", pathItem);
        api.setPaths(paths);
        
        return api;
    }
    
    private OpenAPI createAPIWithFileParam() {
        OpenAPI api = new OpenAPI();
        api.setInfo(new Info().title("Test API"));
        
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        
        Operation operation = new Operation();
        io.swagger.v3.oas.models.parameters.Parameter param = new QueryParameter();
        param.setName("filename");
        param.setSchema(new Schema().type("string"));
        operation.addParametersItem(param);
        
        pathItem.setGet(operation);
        paths.addPathItem("/files/read", pathItem);
        api.setPaths(paths);
        
        return api;
    }
    
    private OpenAPI createAPIWithRegexParam() {
        OpenAPI api = new OpenAPI();
        api.setInfo(new Info().title("Test API"));
        
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        
        Operation operation = new Operation();
        io.swagger.v3.oas.models.parameters.Parameter param = new QueryParameter();
        param.setName("regexPattern");
        param.setSchema(new Schema().type("string"));
        operation.addParametersItem(param);
        
        pathItem.setPost(operation);
        paths.addPathItem("/validate", pathItem);
        api.setPaths(paths);
        
        return api;
    }
    
    private OpenAPI createAPIWithGraphQL() {
        OpenAPI api = new OpenAPI();
        api.setInfo(new Info().title("Test API"));
        
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        
        Operation operation = new Operation();
        io.swagger.v3.oas.models.parameters.Parameter param = new QueryParameter();
        param.setName("graphqlQuery");
        param.setSchema(new Schema().type("string"));
        operation.addParametersItem(param);
        
        pathItem.setPost(operation);
        paths.addPathItem("/graphql", pathItem);
        api.setPaths(paths);
        
        return api;
    }
    
    private OpenAPI createAPIWithIoTParam() {
        OpenAPI api = new OpenAPI();
        api.setInfo(new Info().title("Test API"));
        
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        
        Operation operation = new Operation();
        io.swagger.v3.oas.models.parameters.Parameter param = new QueryParameter();
        param.setName("deviceId");
        param.setSchema(new Schema().type("string"));
        operation.addParametersItem(param);
        
        pathItem.setPost(operation);
        paths.addPathItem("/devices/update", pathItem);
        api.setPaths(paths);
        
        return api;
    }
    
    private OpenAPI createAPIWithOpenBankingParam() {
        OpenAPI api = new OpenAPI();
        api.setInfo(new Info().title("Test API"));
        
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        
        Operation operation = new Operation();
        io.swagger.v3.oas.models.parameters.Parameter param = new QueryParameter();
        param.setName("psd2ConsentId");
        param.setSchema(new Schema().type("string"));
        operation.addParametersItem(param);
        
        pathItem.setPost(operation);
        paths.addPathItem("/banking/consent", pathItem);
        api.setPaths(paths);
        
        return api;
    }
    
    private OpenAPI createAPIWithDangerousFields() {
        OpenAPI api = new OpenAPI();
        api.setInfo(new Info().title("Test API"));
        
        Paths paths = new Paths();
        PathItem pathItem = new PathItem();
        
        Operation operation = new Operation();
        
        // Request body с опасными полями
        RequestBody requestBody = new RequestBody();
        Content content = new Content();
        MediaType mediaType = new MediaType();
        
        Schema schema = new Schema();
        Map<String, Schema> properties = new HashMap<>();
        properties.put("username", new Schema().type("string"));
        properties.put("role", new Schema().type("string")); // ОПАСНОЕ!
        properties.put("isAdmin", new Schema().type("boolean")); // ОПАСНОЕ!
        properties.put("balance", new Schema().type("number")); // ОПАСНОЕ!
        schema.setProperties(properties);
        
        mediaType.setSchema(schema);
        content.addMediaType("application/json", mediaType);
        requestBody.setContent(content);
        operation.setRequestBody(requestBody);
        
        pathItem.setPost(operation);
        paths.addPathItem("/users/create", pathItem);
        api.setPaths(paths);
        
        return api;
    }
}

