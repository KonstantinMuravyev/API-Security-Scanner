package com.vtb.scanner.asyncapi;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Тесты для AsyncAPIParser
 */
class AsyncAPIParserTest {
    
    @Test
    void testParseAsyncAPI() {
        AsyncAPIParser parser = new AsyncAPIParser();
        parser.parseFromFile("examples/asyncapi-example.yaml");
        
        AsyncAPIParser.AsyncAPIInfo info = parser.getInfo();
        
        assertNotNull(info);
        assertEquals("Stock Trading AsyncAPI", info.getTitle());
        assertEquals("1.0.0", info.getVersion());
    }
    
    @Test
    void testGetChannels() {
        AsyncAPIParser parser = new AsyncAPIParser();
        parser.parseFromFile("examples/asyncapi-example.yaml");
        
        var channels = parser.getChannels();
        
        assertNotNull(channels);
        assertTrue(channels.size() > 0, "Должны быть каналы");
    }
    
    @Test
    void testSecurityCheck() {
        AsyncAPIParser parser = new AsyncAPIParser();
        parser.parseFromFile("examples/asyncapi-example.yaml");
        
        boolean hasSecurity = parser.hasSecurity();
        
        assertFalse(hasSecurity, "В примере нет security - это уязвимость");
    }
}

