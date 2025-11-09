package com.vtb.scanner.integration;

import com.vtb.scanner.models.Vulnerability;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты для TLSAnalyzer
 */
class TLSAnalyzerTest {
    
    @Test
    void testAnalyzeTLS_RealHTTPS() {
        // Тест на реальном HTTPS
        TLSAnalyzer analyzer = new TLSAnalyzer("https://jsonplaceholder.typicode.com");
        
        List<Vulnerability> vulns = analyzer.analyzeTLS();
        
        assertNotNull(vulns);
        // Должны найти ГОСТ нарушения (это не российский сервер)
        assertTrue(vulns.stream().anyMatch(v -> v.isGostRelated()), 
            "Должны быть ГОСТ нарушения на зарубежном сервере");
    }
    
    @Test
    void testAnalyzeTLS_HTTP() {
        // HTTP - не должно быть TLS анализа
        TLSAnalyzer analyzer = new TLSAnalyzer("http://example.com");
        
        List<Vulnerability> vulns = analyzer.analyzeTLS();
        
        assertNotNull(vulns);
        assertEquals(0, vulns.size(), "Для HTTP не должно быть TLS проверок");
    }
    
    @Test
    void testRussianCAValidator() {
        assertTrue(RussianCAValidator.isRussianAccreditedCA("CN=CryptoPro"));
        assertTrue(RussianCAValidator.isRussianAccreditedCA("CN=Signal-COM"));
        assertFalse(RussianCAValidator.isRussianAccreditedCA("CN=Let's Encrypt"));
        assertFalse(RussianCAValidator.isRussianAccreditedCA("CN=Google Trust Services"));
    }
}

