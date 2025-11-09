package com.vtb.scanner.asyncapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Сканер безопасности для AsyncAPI
 * Проверяет уязвимости в асинхронных API (WebSocket, MQTT, Kafka)
 */
@Slf4j
public class AsyncAPIScanner {
    
    private final AsyncAPIParser parser;
    
    public AsyncAPIScanner(AsyncAPIParser parser) {
        this.parser = parser;
    }
    
    /**
     * Сканирование AsyncAPI на уязвимости
     */
    public List<Vulnerability> scan() {
        log.info("Запуск AsyncAPI Scanner...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (parser == null) {
            log.warn("Parser не инициализирован, пропускаем сканирование");
            return vulnerabilities;
        }
        
        // 1. Проверка security
        vulnerabilities.addAll(checkSecurity());
        
        // 2. Проверка каналов
        vulnerabilities.addAll(checkChannels());
        
        log.info("AsyncAPI Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkSecurity() {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (parser == null) {
            return vulnerabilities;
        }
        
        if (!parser.hasSecurity()) {
            vulnerabilities.add(Vulnerability.builder()
                .id("ASYNC-NO-SECURITY")
                .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                .severity(Severity.HIGH)
                .title("AsyncAPI без аутентификации")
                .description(
                    "Асинхронный API не определяет схемы аутентификации. " +
                    "WebSocket/MQTT соединения должны быть защищены!"
                )
                .endpoint("AsyncAPI")
                .method("N/A")
                .recommendation(
                    "Добавьте security schemes:\n" +
                    "• WebSocket: token в URL или первом сообщении\n" +
                    "• MQTT: username/password или certificate\n" +
                    "• Kafka: SASL/SSL"
                )
                .owaspCategory("API2:2023 - Broken Authentication")
                .evidence("Секция security отсутствует")
                .build());
        }
        
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkChannels() {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (parser == null) {
            return vulnerabilities;
        }
        
        Map<String, JsonNode> channels = parser.getChannels();
        if (channels == null || channels.isEmpty()) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, JsonNode> entry : channels.entrySet()) {
            String channelName = entry.getKey();
            JsonNode channel = entry.getValue();
            
            // КРИТИЧНО: Защита от null
            if (channelName == null || channel == null) {
                continue;
            }
            
            // Проверяем subscribe операции (потребление сообщений)
            if (channel.has("subscribe")) {
                JsonNode subscribe = channel.get("subscribe");
                
                // КРИТИЧНО: Защита от null
                if (subscribe != null) {
                    // Проверка security для конкретного канала
                    if (!subscribe.has("security") && !parser.hasSecurity()) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.BROKEN_AUTHENTICATION, channelName, "SUBSCRIBE", null,
                            "Канал без аутентификации"))
                        .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                        .severity(Severity.MEDIUM)
                        .title("Канал без аутентификации")
                        .description(
                            "Канал '" + channelName + "' позволяет subscribe без аутентификации. " +
                            "Любой может подписаться на сообщения!"
                        )
                        .endpoint(channelName)
                        .method("SUBSCRIBE")
                        .recommendation(
                            "Добавьте аутентификацию для канала или глобально в AsyncAPI"
                        )
                        .owaspCategory("API2:2023 - Broken Authentication (AsyncAPI)")
                        .evidence("subscribe без security")
                        .build());
                    }
                }
            }
        }
        
        return vulnerabilities;
    }
}

