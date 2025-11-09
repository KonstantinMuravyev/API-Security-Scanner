package com.vtb.scanner.heuristics;

import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * СТРОГИЕ тесты для 14 новых паттернов EnhancedRules
 * Проверяют ВСЕ новые методы: Crypto, RU Pay, Path Traversal, NoSQL, etc.
 */
class EnhancedRulesAdvancedTest {
    
    // ═══════════════════════════════════════════════════════════════
    // CRYPTO / BLOCKCHAIN PATTERNS
    // ═══════════════════════════════════════════════════════════════
    
    @Test
    void testIsCryptoRisk_WalletParameter() {
        Parameter param = new Parameter();
        param.setName("walletAddress");
        
        assertTrue(EnhancedRules.isCryptoRisk(param), 
            "walletAddress должен быть Crypto риском");
    }
    
    @Test
    void testIsCryptoRisk_Bitcoin() {
        Parameter param = new Parameter();
        param.setName("btcAddress");
        
        assertTrue(EnhancedRules.isCryptoRisk(param), 
            "btcAddress должен быть Crypto риском");
    }
    
    @Test
    void testIsCryptoRisk_Ethereum() {
        Parameter param = new Parameter();
        param.setName("ethWallet");
        
        assertTrue(EnhancedRules.isCryptoRisk(param), 
            "ethWallet должен быть Crypto риском");
    }
    
    @Test
    void testIsCryptoRisk_Blockchain() {
        Parameter param = new Parameter();
        param.setName("blockchainHash");
        
        assertTrue(EnhancedRules.isCryptoRisk(param), 
            "blockchainHash должен быть Crypto риском");
    }
    
    @Test
    void testIsCryptoRisk_PrivateKey() {
        Parameter param = new Parameter();
        param.setName("privateKey");
        
        assertTrue(EnhancedRules.isCryptoRisk(param), 
            "privateKey должен быть Crypto риском");
    }
    
    @Test
    void testIsCryptoRisk_Mnemonic() {
        Parameter param = new Parameter();
        param.setName("mnemonic");
        
        assertTrue(EnhancedRules.isCryptoRisk(param), 
            "mnemonic должен быть Crypto риском");
    }
    
    @Test
    void testIsCryptoRisk_FalsePositive() {
        Parameter param = new Parameter();
        param.setName("username");
        
        assertFalse(EnhancedRules.isCryptoRisk(param), 
            "username НЕ должен быть Crypto риском");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // RUSSIAN PAYMENT SYSTEMS
    // ═══════════════════════════════════════════════════════════════
    
    @Test
    void testIsRussianPaymentRisk_SBP() {
        Parameter param = new Parameter();
        param.setName("sbpPayment");
        
        assertTrue(EnhancedRules.isRussianPaymentRisk(param), 
            "sbpPayment должен быть Russian Payment риском");
    }
    
    @Test
    void testIsRussianPaymentRisk_MIR() {
        Parameter param = new Parameter();
        param.setName("mirCardNumber");
        
        assertTrue(EnhancedRules.isRussianPaymentRisk(param), 
            "mirCardNumber должен быть Russian Payment риском");
    }
    
    @Test
    void testIsRussianPaymentRisk_QIWI() {
        Parameter param = new Parameter();
        param.setName("qiwiWallet");
        
        assertTrue(EnhancedRules.isRussianPaymentRisk(param), 
            "qiwiWallet должен быть Russian Payment риском");
    }
    
    @Test
    void testIsRussianPaymentRisk_Yoomoney() {
        Parameter param = new Parameter();
        param.setName("yoomoney");
        
        assertTrue(EnhancedRules.isRussianPaymentRisk(param), 
            "yoomoney должен быть Russian Payment риском");
    }
    
    @Test
    void testIsRussianPaymentRisk_Rubles() {
        Parameter param = new Parameter();
        param.setName("amountRub");
        
        assertTrue(EnhancedRules.isRussianPaymentRisk(param), 
            "amountRub должен быть Russian Payment риском");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // PATH TRAVERSAL / LFI
    // ═══════════════════════════════════════════════════════════════
    
    @Test
    void testIsPathTraversalRisk_File() {
        Parameter param = new Parameter();
        param.setName("filename");
        
        assertTrue(EnhancedRules.isPathTraversalRisk(param), 
            "filename должен быть Path Traversal риском");
    }
    
    @Test
    void testIsPathTraversalRisk_Path() {
        Parameter param = new Parameter();
        param.setName("filePath");
        
        assertTrue(EnhancedRules.isPathTraversalRisk(param), 
            "filePath должен быть Path Traversal риском");
    }
    
    @Test
    void testIsPathTraversalRisk_Directory() {
        Parameter param = new Parameter();
        param.setName("directory");
        
        assertTrue(EnhancedRules.isPathTraversalRisk(param), 
            "directory должен быть Path Traversal риском");
    }
    
    @Test
    void testIsPathTraversalRisk_Template() {
        Parameter param = new Parameter();
        param.setName("template");
        
        assertTrue(EnhancedRules.isPathTraversalRisk(param), 
            "template должен быть Path Traversal риском");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // NOSQL INJECTION
    // ═══════════════════════════════════════════════════════════════
    
    @Test
    void testIsNoSQLRisk_Mongo() {
        Parameter param = new Parameter();
        param.setName("mongoQuery");
        
        assertTrue(EnhancedRules.isNoSQLRisk(param), 
            "mongoQuery должен быть NoSQL риском");
    }
    
    @Test
    void testIsNoSQLRisk_Aggregate() {
        Parameter param = new Parameter();
        param.setName("aggregatePipeline");
        
        assertTrue(EnhancedRules.isNoSQLRisk(param), 
            "aggregatePipeline должен быть NoSQL риском");
    }
    
    @Test
    void testIsNoSQLRisk_CaseInsensitive() {
        Parameter param = new Parameter();
        param.setName("MONGODB");
        
        assertTrue(EnhancedRules.isNoSQLRisk(param), 
            "MONGODB (верхний регистр) должен быть NoSQL риском");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // TEMPLATE INJECTION (SSTI)
    // ═══════════════════════════════════════════════════════════════
    
    @Test
    void testIsTemplateInjectionRisk_Template() {
        Parameter param = new Parameter();
        param.setName("templateName");
        
        assertTrue(EnhancedRules.isTemplateInjectionRisk(param), 
            "templateName должен быть SSTI риском");
    }
    
    @Test
    void testIsTemplateInjectionRisk_Render() {
        Parameter param = new Parameter();
        param.setName("renderTemplate");
        
        assertTrue(EnhancedRules.isTemplateInjectionRisk(param), 
            "renderTemplate должен быть SSTI риском");
    }
    
    @Test
    void testIsTemplateInjectionRisk_Jinja() {
        Parameter param = new Parameter();
        param.setName("jinjaExpression");
        
        assertTrue(EnhancedRules.isTemplateInjectionRisk(param), 
            "jinjaExpression должен быть SSTI риском");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // LDAP INJECTION
    // ═══════════════════════════════════════════════════════════════
    
    @Test
    void testIsLDAPRisk_LDAP() {
        Parameter param = new Parameter();
        param.setName("ldapQuery");
        
        assertTrue(EnhancedRules.isLDAPRisk(param), 
            "ldapQuery должен быть LDAP риском");
    }
    
    @Test
    void testIsLDAPRisk_DN() {
        Parameter param = new Parameter();
        param.setName("distinguishedName");
        
        assertTrue(EnhancedRules.isLDAPRisk(param), 
            "distinguishedName должен быть LDAP риском");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // DESERIALIZATION
    // ═══════════════════════════════════════════════════════════════
    
    @Test
    void testIsDeserializationRisk_Serialize() {
        Parameter param = new Parameter();
        param.setName("serializedData");
        
        assertTrue(EnhancedRules.isDeserializationRisk(param), 
            "serializedData должен быть Deserialization риском");
    }
    
    @Test
    void testIsDeserializationRisk_Pickle() {
        Parameter param = new Parameter();
        param.setName("pickleObject");
        
        assertTrue(EnhancedRules.isDeserializationRisk(param), 
            "pickleObject должен быть Deserialization риском");
    }
    
    @Test
    void testIsDeserializationRisk_Unmarshal() {
        Parameter param = new Parameter();
        param.setName("unmarshalData");
        
        assertTrue(EnhancedRules.isDeserializationRisk(param), 
            "unmarshalData должен быть Deserialization риском");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // GRAPHQL
    // ═══════════════════════════════════════════════════════════════
    
    @Test
    void testIsGraphQLRisk_Query() {
        Parameter param = new Parameter();
        param.setName("graphqlQuery");
        
        assertTrue(EnhancedRules.isGraphQLRisk(param), 
            "graphqlQuery должен быть GraphQL риском");
    }
    
    @Test
    void testIsGraphQLRisk_Mutation() {
        Parameter param = new Parameter();
        param.setName("mutation");
        
        assertTrue(EnhancedRules.isGraphQLRisk(param), 
            "mutation должен быть GraphQL риском");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // XML / XXE
    // ═══════════════════════════════════════════════════════════════
    
    @Test
    void testIsXMLRisk_XML() {
        Parameter param = new Parameter();
        param.setName("xmlData");
        
        assertTrue(EnhancedRules.isXMLRisk(param), 
            "xmlData должен быть XXE риском");
    }
    
    @Test
    void testIsXMLRisk_SOAP() {
        Parameter param = new Parameter();
        param.setName("soapRequest");
        
        assertTrue(EnhancedRules.isXMLRisk(param), 
            "soapRequest должен быть XXE риском");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // REDOS
    // ═══════════════════════════════════════════════════════════════
    
    @Test
    void testIsReDoSRisk_Regex() {
        Parameter param = new Parameter();
        param.setName("regexPattern");
        
        assertTrue(EnhancedRules.isReDoSRisk(param), 
            "regexPattern должен быть ReDoS риском");
    }
    
    @Test
    void testIsReDoSRisk_Pattern() {
        Parameter param = new Parameter();
        param.setName("matchPattern");
        
        assertTrue(EnhancedRules.isReDoSRisk(param), 
            "matchPattern должен быть ReDoS риском");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // IOT
    // ═══════════════════════════════════════════════════════════════
    
    @Test
    void testIsIoTRisk_Device() {
        Parameter param = new Parameter();
        param.setName("deviceId");
        
        assertTrue(EnhancedRules.isIoTRisk(param), 
            "deviceId должен быть IoT риском");
    }
    
    @Test
    void testIsIoTRisk_Firmware() {
        Parameter param = new Parameter();
        param.setName("firmwareUpdate");
        
        assertTrue(EnhancedRules.isIoTRisk(param), 
            "firmwareUpdate должен быть IoT риском");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // OPEN BANKING / PSD2
    // ═══════════════════════════════════════════════════════════════
    
    @Test
    void testIsOpenBankingRisk_PSD2() {
        Parameter param = new Parameter();
        param.setName("psd2Consent");
        
        assertTrue(EnhancedRules.isOpenBankingRisk(param), 
            "psd2Consent должен быть Open Banking риском");
    }
    
    @Test
    void testIsOpenBankingRisk_Consent() {
        Parameter param = new Parameter();
        param.setName("consentId");
        
        assertTrue(EnhancedRules.isOpenBankingRisk(param), 
            "consentId должен быть Open Banking риском");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // JWT CLAIMS
    // ═══════════════════════════════════════════════════════════════
    
    @Test
    void testFindDangerousJWTClaims_Alg() {
        Schema schema = new Schema();
        Map<String, Schema> properties = new HashMap<>();
        properties.put("alg", new Schema());
        properties.put("typ", new Schema());
        schema.setProperties(properties);
        
        List<String> dangerous = EnhancedRules.findDangerousJWTClaims(schema);
        
        assertTrue(dangerous.contains("alg"), 
            "'alg' должен быть в опасных JWT claims");
        assertTrue(dangerous.contains("typ"), 
            "'typ' должен быть в опасных JWT claims");
    }
    
    @Test
    void testFindDangerousJWTClaims_Role() {
        Schema schema = new Schema();
        Map<String, Schema> properties = new HashMap<>();
        properties.put("role", new Schema());
        properties.put("permissions", new Schema());
        schema.setProperties(properties);
        
        List<String> dangerous = EnhancedRules.findDangerousJWTClaims(schema);
        
        assertTrue(dangerous.contains("role"), 
            "'role' должен быть в опасных JWT claims");
        assertTrue(dangerous.contains("permissions"), 
            "'permissions' должны быть в опасных JWT claims");
    }
    
    // ═══════════════════════════════════════════════════════════════
    // MASS ASSIGNMENT
    // ═══════════════════════════════════════════════════════════════
    
    @Test
    void testHasDangerousFields_Role() {
        Schema schema = new Schema();
        Map<String, Schema> properties = new HashMap<>();
        properties.put("role", new Schema());
        schema.setProperties(properties);
        
        assertTrue(EnhancedRules.hasDangerousFields(schema), 
            "Schema с 'role' должна иметь опасные поля");
    }
    
    @Test
    void testHasDangerousFields_IsAdmin() {
        Schema schema = new Schema();
        Map<String, Schema> properties = new HashMap<>();
        properties.put("isAdmin", new Schema());
        schema.setProperties(properties);
        
        assertTrue(EnhancedRules.hasDangerousFields(schema), 
            "Schema с 'isAdmin' должна иметь опасные поля");
    }
    
    @Test
    void testHasDangerousFields_Balance() {
        Schema schema = new Schema();
        Map<String, Schema> properties = new HashMap<>();
        properties.put("balance", new Schema());
        schema.setProperties(properties);
        
        assertTrue(EnhancedRules.hasDangerousFields(schema), 
            "Schema с 'balance' должна иметь опасные поля");
    }
    
    @Test
    void testHasDangerousFields_Price() {
        Schema schema = new Schema();
        Map<String, Schema> properties = new HashMap<>();
        properties.put("price", new Schema());
        schema.setProperties(properties);
        
        assertTrue(EnhancedRules.hasDangerousFields(schema), 
            "Schema с 'price' должна иметь опасные поля");
    }
    
    @Test
    void testHasDangerousFields_Safe() {
        Schema schema = new Schema();
        Map<String, Schema> properties = new HashMap<>();
        properties.put("username", new Schema());
        properties.put("email", new Schema());
        schema.setProperties(properties);
        
        assertFalse(EnhancedRules.hasDangerousFields(schema), 
            "Schema без опасных полей должна вернуть false");
    }
}

