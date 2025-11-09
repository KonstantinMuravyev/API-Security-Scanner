package com.vtb.scanner.asyncapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.nio.file.Files;
import java.util.*;

/**
 * Парсер AsyncAPI 2.6+ спецификаций
 * Поддержка асинхронных API (WebSocket, MQTT, Kafka, etc.)
 */
@Slf4j
public class AsyncAPIParser {
    
    private JsonNode asyncAPI;
    private String version;
    
    /**
     * Парсинг AsyncAPI спецификации
     */
    public void parseFromFile(String filePath) {
        log.info("Загрузка AsyncAPI спецификации: {}", filePath);
        
        // КРИТИЧНО: Валидация входных данных
        if (filePath == null || filePath.trim().isEmpty()) {
            throw new IllegalArgumentException("Путь к файлу не может быть null или пустым");
        }
        
        try {
            File file = new File(filePath);
            if (!file.exists()) {
                throw new IllegalArgumentException("Файл не найден: " + filePath);
            }
            
            if (!file.isFile()) {
                throw new IllegalArgumentException("Путь не является файлом: " + filePath);
            }
            
            // КРИТИЧНО: Проверка размера файла для предотвращения утечки памяти
            long fileSize = file.length();
            long maxFileSizeMB = 100; // 100 MB лимит для AsyncAPI
            if (fileSize > maxFileSizeMB * 1024 * 1024) {
                throw new IllegalArgumentException(
                    String.format("Файл слишком большой: %.2f MB (максимум: %d MB)", 
                        fileSize / (1024.0 * 1024.0), maxFileSizeMB));
            }
            
            String content = Files.readString(file.toPath());
            
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            this.asyncAPI = mapper.readTree(content);
            
            // КРИТИЧНО: Проверка что парсинг успешен
            if (this.asyncAPI == null) {
                throw new IllegalArgumentException("Не удалось распарсить файл");
            }
            
            // Проверяем что это AsyncAPI
            if (!asyncAPI.has("asyncapi")) {
                throw new IllegalArgumentException("Это не AsyncAPI спецификация");
            }
            
            this.version = asyncAPI.get("asyncapi").asText();
            if (this.version == null) {
                throw new IllegalArgumentException("Версия AsyncAPI не найдена");
            }
            
            log.info("AsyncAPI версия: {}", version);
            
            // Поддерживаем 2.x
            if (!version.startsWith("2.")) {
                log.warn("Версия {} может быть не полностью поддержана. Рекомендуется 2.6+", version);
            }
            
        } catch (IllegalArgumentException e) {
            throw e; // Пробрасываем как есть
        } catch (Exception e) {
            throw new RuntimeException("Ошибка парсинга AsyncAPI: " + e.getMessage(), e);
        }
    }
    
    /**
     * Получить информацию об API
     */
    public AsyncAPIInfo getInfo() {
        AsyncAPIInfo info = new AsyncAPIInfo();
        
        // КРИТИЧНО: Защита от NPE
        if (asyncAPI == null) {
            return info; // Возвращаем пустой объект
        }
        
        if (asyncAPI.has("info")) {
            JsonNode infoNode = asyncAPI.get("info");
            if (infoNode != null) {
                info.setTitle(infoNode.has("title") ? infoNode.get("title").asText() : "Unknown");
                info.setVersion(infoNode.has("version") ? infoNode.get("version").asText() : "Unknown");
                info.setDescription(infoNode.has("description") ? infoNode.get("description").asText() : "");
            }
        }
        
        return info;
    }
    
    /**
     * Получить все каналы (channels)
     */
    public Map<String, JsonNode> getChannels() {
        Map<String, JsonNode> channels = new HashMap<>();
        
        // КРИТИЧНО: Защита от NPE
        if (asyncAPI == null || !asyncAPI.has("channels")) {
            return channels;
        }
        
        JsonNode channelsNode = asyncAPI.get("channels");
        if (channelsNode != null) {
            channelsNode.fields().forEachRemaining(entry -> {
                if (entry.getKey() != null && entry.getValue() != null) {
                    channels.put(entry.getKey(), entry.getValue());
                }
            });
        }
        
        return channels;
    }
    
    /**
     * Проверить есть ли security
     */
    public boolean hasSecurity() {
        // КРИТИЧНО: Защита от NPE
        if (asyncAPI == null) {
            return false;
        }
        
        if (asyncAPI.has("security")) {
            JsonNode securityNode = asyncAPI.get("security");
            if (securityNode != null && securityNode.size() > 0) {
                return true;
            }
        }
        
        // Проверяем в servers
        if (asyncAPI.has("servers")) {
            JsonNode servers = asyncAPI.get("servers");
            if (servers != null && servers.isArray()) {
                for (JsonNode server : servers) {
                    if (server != null && server.has("security")) {
                        JsonNode serverSecurity = server.get("security");
                        if (serverSecurity != null && serverSecurity.size() > 0) {
                            return true;
                        }
                    }
                }
            }
        }
        
        return false;
    }
    
    @Data
    public static class AsyncAPIInfo {
        private String title;
        private String version;
        private String description;
    }
}

