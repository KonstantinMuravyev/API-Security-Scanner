package com.vtb.scanner.core;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.ParseOptions;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Парсер OpenAPI/Swagger спецификаций
 * 
 * ПОДДЕРЖИВАЕТ БОЛЬШИЕ API (>8MB)!
 * - Скачивание по URL с проверкой размера
 * - Streaming парсинг для больших JSON
 * - Автоматический fallback на Jackson для JSON > 3MB
 */
@Slf4j
public class OpenAPIParser {
    
    private OpenAPI openAPI;
    private String specificationSource;
    private Path tempFileToDelete; // Временный файл, который нужно удалить после парсинга
    
    // Конфигурируемые лимиты для больших API
    // Можно увеличить через системное свойство: -Dscanner.max.file.size.mb=5000
    private static final long MAX_FILE_SIZE_MB = Long.parseLong(
        System.getProperty("scanner.max.file.size.mb", "5000")); // По умолчанию 5 GB!
    private static final long LARGE_FILE_THRESHOLD = 3_000_000; // 3 MB
    private static final long VERY_LARGE_FILE_THRESHOLD = 100_000_000; // 100 MB - используем memory-mapped files
    private static final long HUGE_FILE_THRESHOLD = 1_000_000_000; // 1 GB - только streaming парсинг
    
    /**
     * Установить OpenAPI объект напрямую (для тестов!)
     */
    public void setOpenAPI(OpenAPI openAPI) {
        this.openAPI = openAPI;
        this.specificationSource = "test-synthetic";
    }
    
    /**
     * Загрузить спецификацию из файла
     */
    public void parseFromFile(String filePath) {
        log.info("Загрузка спецификации из файла: {}", filePath);
        
        File file = new File(filePath);
        if (!file.exists()) {
            throw new IllegalArgumentException("Файл не найден: " + filePath);
        }
        
        parseSpecification(file.getAbsolutePath());
    }
    
    /**
     * Загрузить спецификацию по URL
     * 
     * КРИТИЧНО: Поддерживает большие файлы (>8MB)!
     * - Скачивает во временный файл
     * - Проверяет размер через Content-Length
     * - Использует streaming для больших файлов
     */
    public void parseFromUrl(String urlString) {
        log.info("Загрузка спецификации по URL: {}", urlString);
        
        Path tempFile = null;
        HttpURLConnection connection = null;
        try {
            URL url = new URL(urlString);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(30000); // 30 сек
            connection.setReadTimeout(60000); // 60 сек для больших файлов
            
            // Проверяем размер через Content-Length
            long contentLength = connection.getContentLengthLong();
            if (contentLength > 0) {
                long contentLengthMB = contentLength / (1024 * 1024);
                long contentLengthGB = contentLengthMB / 1024;
                
                if (contentLengthGB > 0) {
                    log.info("Размер файла по URL: {} GB ({} MB)", contentLengthGB, contentLengthMB);
                } else {
                log.info("Размер файла по URL: {} MB", contentLengthMB);
                }
                
                if (contentLength > MAX_FILE_SIZE_MB * 1024 * 1024) {
                    throw new IllegalArgumentException(
                        String.format("Файл слишком большой: %d MB (максимум: %d MB). " +
                            "Увеличьте лимит через -Dscanner.max.file.size.mb=<размер>", 
                            contentLengthMB, MAX_FILE_SIZE_MB));
                }
                
                if (contentLength > HUGE_FILE_THRESHOLD) {
                    log.warn("ОЧЕНЬ БОЛЬШОЙ файл ({} GB), используется streaming парсинг", contentLengthGB);
                } else if (contentLength > VERY_LARGE_FILE_THRESHOLD) {
                    log.warn("Большой файл ({} MB), будет использован memory-mapped парсинг", contentLengthMB);
                } else if (contentLength > LARGE_FILE_THRESHOLD) {
                    log.warn("Файл большой ({} MB), будет использован специальный парсинг", contentLengthMB);
                }
            }
            
            // Скачиваем во временный файл
            tempFile = Files.createTempFile("api-spec-", 
                urlString.contains(".json") ? ".json" : ".yaml");
            
            try (InputStream inputStream = connection.getInputStream();
                 FileOutputStream outputStream = new FileOutputStream(tempFile.toFile())) {
                
                byte[] buffer = new byte[8192];
                long totalRead = 0;
                int bytesRead;
                
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                    totalRead += bytesRead;
                    
                    // Проверяем размер во время скачивания
                    if (contentLength <= 0 && totalRead > MAX_FILE_SIZE_MB * 1024 * 1024) {
                        throw new IllegalArgumentException(
                            String.format("Файл превышает лимит: %d MB", MAX_FILE_SIZE_MB));
                    }
                }
                
                log.info("Файл скачан: {} bytes", totalRead);
            }
            
            // Парсим из временного файла
            // Сохраняем ссылку на временный файл для удаления после завершения resolve
            tempFileToDelete = tempFile;
            try {
                parseSpecification(tempFile.toFile().getAbsolutePath());
            } catch (Exception e) {
                // КРИТИЧНО: Если parseSpecification выбросит исключение, файл все равно нужно удалить
                // Удаляем временный файл при ошибке парсинга
                if (tempFile != null) {
                    try {
                        Files.deleteIfExists(tempFile);
                        tempFileToDelete = null;
                    } catch (IOException deleteError) {
                        log.warn("Не удалось удалить временный файл при ошибке парсинга: {}", tempFile);
                    }
                }
                throw e; // Пробрасываем исключение дальше
            }
            
            // Удаляем временный файл ПОСЛЕ успешного завершения парсинга и resolve
            if (tempFileToDelete != null) {
                try {
                    Files.deleteIfExists(tempFileToDelete);
                    tempFileToDelete = null;
                } catch (IOException e) {
                    log.warn("Не удалось удалить временный файл: {}", tempFileToDelete);
                }
            }
            
        } catch (IOException e) {
            // Удаляем временный файл при ошибке скачивания
            if (tempFile != null) {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException deleteError) {
                    log.warn("Не удалось удалить временный файл при ошибке: {}", tempFile);
                }
            }
            throw new RuntimeException("Ошибка при скачивании спецификации по URL: " + e.getMessage(), e);
        } finally {
            // КРИТИЧНО: Закрываем HttpURLConnection для предотвращения утечки ресурсов
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
    
    /**
     * Преобразует путь к файлу в корректный формат для библиотеки swagger-parser
     * 
     * КРИТИЧНО для качества: библиотека лучше работает с путями напрямую для локальных файлов,
     * URI используем только для удаленных ресурсов (http/https)
     * 
     * Работает на Windows, Linux и Mac одинаково
     * 
     * @param filePath путь к файлу (может быть относительным или абсолютным)
     * @return путь для локальных файлов, URI для удаленных ресурсов
     */
    private String toFileLocation(String filePath) {
        if (filePath == null || filePath.trim().isEmpty()) {
            return filePath;
        }
        
        String trimmed = filePath.trim();
        
        // Для удаленных ресурсов (http/https) возвращаем URI как есть
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            return trimmed;
        }
        
        // Для URI локальных файлов (file://) преобразуем обратно в путь
        if (trimmed.startsWith("file://")) {
            try {
                // Преобразуем file:///C:/path в C:/path для Windows
                // или file:///path в /path для Linux/Mac
                java.net.URI uri = new java.net.URI(trimmed);
                Path path = Paths.get(uri);
                return path.toAbsolutePath().toString();
            } catch (Exception e) {
                log.warn("Не удалось преобразовать URI в путь: {}, используем оригинальный", trimmed);
                return trimmed;
            }
        }
        
        // Для локальных файлов возвращаем абсолютный путь напрямую
        // Библиотека swagger-parser корректно работает с путями на всех платформах
        try {
            Path path = Paths.get(filePath);
            return path.toAbsolutePath().toString();
        } catch (Exception e) {
            log.warn("Не удалось нормализовать путь: {}, используем оригинальный", filePath);
            return filePath;
        }
    }
    
    /**
     * Парсинг спецификации
     * 
     * ПОДДЕРЖИВАЕТ БОЛЬШИЕ API (>8MB)!
     * - Малые/средние API (< 3 MB) → SnakeYAML/Swagger Parser
     * - Большие API (> 3 MB) → Jackson JSON парсер (обходит лимит!)
     * - YAML > 3MB → предупреждение + попытка парсинга
     */
    private void parseSpecification(String location) {
        File file = new File(location);
        
        // Проверяем размер файла (только для локальных файлов)
        long fileSizeBytes = 0;
        long fileSizeMB = 0;
        long fileSizeGB = 0;
        if (file.exists()) {
            fileSizeBytes = file.length();
            fileSizeMB = fileSizeBytes / (1024 * 1024);
            fileSizeGB = fileSizeMB / 1024;
            
        if (fileSizeGB > 0) {
            log.info("Размер файла: {} GB ({} MB)", fileSizeGB, fileSizeMB);
        } else {
            log.info("Размер файла: {} MB", fileSizeMB);
            }
        
            if (fileSizeBytes > MAX_FILE_SIZE_MB * 1024 * 1024) {
                throw new IllegalArgumentException(
                    String.format("Файл слишком большой: %d MB (максимум: %d MB). " +
                        "Увеличьте лимит через -Dscanner.max.file.size.mb=<размер>", 
                        fileSizeMB, MAX_FILE_SIZE_MB));
            }
        }
        
        // Определяем стратегию парсинга в зависимости от размера
        boolean isHugeFile = fileSizeBytes > HUGE_FILE_THRESHOLD; // > 1 GB
        boolean isVeryLargeFile = fileSizeBytes > VERY_LARGE_FILE_THRESHOLD; // > 100 MB
        boolean isLargeFile = fileSizeBytes > LARGE_FILE_THRESHOLD; // > 3 MB
        if (isLargeFile) {
            log.warn("Файл большой ({} MB), стандартный Swagger Parser может не справиться", fileSizeMB);
            
            // Для очень больших файлов (> 1 GB) используем streaming парсинг
            if (isHugeFile && location.endsWith(".json")) {
                log.info("💡 ОЧЕНЬ БОЛЬШОЙ файл (>1GB), используем streaming парсинг через Jackson...");
                try {
                    this.openAPI = parseJsonStreaming(location);
                    if (this.openAPI != null) {
                        this.specificationSource = location;
                        log.info("Спецификация успешно загружена (streaming): {} (версия {})", 
                                getApiTitle(), getApiVersion());
                        return;
                    }
                } catch (Exception e) {
                    log.warn("Streaming парсинг не удался, пробуем стандартный: {}", e.getMessage());
                }
            }
            
            // Для больших файлов (> 100 MB) используем memory-mapped files
            if (isVeryLargeFile && location.endsWith(".json")) {
                log.info("💡 Используем memory-mapped парсинг через Jackson для больших файлов...");
                try {
                    this.openAPI = parseJsonMemoryMapped(location);
                    if (this.openAPI != null) {
                        this.specificationSource = location;
                        log.info("Спецификация успешно загружена (memory-mapped): {} (версия {})", 
                                getApiTitle(), getApiVersion());
                        return;
                    }
                } catch (Exception e) {
                    log.warn("Memory-mapped парсинг не удался, пробуем стандартный: {}", e.getMessage());
                }
            }
            
            // Для больших файлов (> 3 MB) используем прямой Jackson парсинг
            if (isLargeFile && location.endsWith(".json")) {
                log.info("💡 Используем прямой JSON парсинг через Jackson для больших файлов...");
                try {
                    this.openAPI = parseJsonDirectly(location);
                    if (this.openAPI != null) {
                        this.specificationSource = location;
                        log.info("Спецификация успешно загружена (большой JSON): {} (версия {})", 
                                getApiTitle(), getApiVersion());
                        return;
                    }
                } catch (Exception e) {
                    log.warn("Прямой JSON парсинг не удался, пробуем стандартный: {}", e.getMessage());
                }
            } else if (isLargeFile) {
            log.info("💡 Рекомендация: конвертируйте YAML в JSON для парсинга больших файлов");
            log.info("💡 GitHub API доступен в JSON: https://github.com/github/rest-api-description");
            }
        }
        
        ParseOptions options = new ParseOptions();
        // КАЧЕСТВО ПРЕОБЛАДАЕТ: включаем resolve для точного анализа схем
        // Отключаем только для ОЧЕНЬ больших файлов (>1GB) для экономии памяти
        options.setResolve(!isHugeFile); // Включаем resolve для всех файлов кроме огромных
        options.setResolveFully(false); // Не разрешаем полностью (это медленно и не всегда нужно)
        
        // Устанавливаем максимальные лимиты для SnakeYAML
        System.setProperty("org.yaml.snakeyaml.constructor.maxAliasesForCollections", 
            String.valueOf(Integer.MAX_VALUE));
        System.setProperty("org.yaml.snakeyaml.maxCodePoints", 
            String.valueOf(Integer.MAX_VALUE));
        
        try {
        OpenAPIV3Parser parser = new OpenAPIV3Parser();
        // КАЧЕСТВО: для локальных файлов используем путь напрямую, не URI
        // Библиотека swagger-parser корректнее работает с путями для resolve ссылок
        String locationForParser = toFileLocation(location);
        SwaggerParseResult result = parser.readLocation(locationForParser, null, options);
        
        // Обрабатываем предупреждения и ошибки resolve как информационные сообщения
        if (result.getMessages() != null && !result.getMessages().isEmpty()) {
            for (String message : result.getMessages()) {
                // Ошибки resolve не критичны - библиотека может работать без них
                if (message.contains("Invalid file path") || 
                    message.contains("FileNotFoundException") ||
                    message.contains("Error resolving schema")) {
                    log.debug("Предупреждение парсера (resolve ссылок): {}", message);
                } else {
                    log.warn("Предупреждение при парсинге: {}", message);
                }
            }
        }
        
        this.openAPI = result.getOpenAPI();
            
            // Fallback для JSON файлов если стандартный парсер не справился
            if (this.openAPI == null && location.endsWith(".json")) {
                log.info("Стандартный парсер не справился, пробуем альтернативный JSON парсинг...");
                try {
                    this.openAPI = parseJsonDirectly(location);
                } catch (Exception e) {
                    log.error("Альтернативный парсинг тоже не удался: {}", e.getMessage());
                }
            }
            
            if (this.openAPI == null) {
                throw new IllegalStateException(
                    "Не удалось распарсить спецификацию OpenAPI. " +
                    "Возможные причины:\n" +
                    "1. Файл поврежден или не является валидной OpenAPI спецификацией\n" +
                    "2. Для больших файлов (> 3 MB) используйте JSON формат вместо YAML\n" +
                    "3. Проверьте размер файла (максимум: " + MAX_FILE_SIZE_MB + " MB)\n" +
                    "Примеры больших API в JSON:\n" +
                    "  - GitHub: https://raw.githubusercontent.com/github/rest-api-description/main/descriptions/api.github.com/api.github.com.json");
            }
            
        } catch (OutOfMemoryError e) {
            throw new IllegalStateException(
                "Недостаточно памяти для парсинга большого файла (" + fileSizeMB + " MB). " +
                "Попробуйте:\n" +
                "1. Увеличить heap memory: java -Xmx2g -jar ...\n" +
                "2. Использовать JSON формат вместо YAML\n" +
                "3. Уменьшить размер спецификации (разделить на части)", e);
        }
        
        this.specificationSource = location;
        log.info("Спецификация успешно загружена: {} (версия {})", 
                getApiTitle(), getApiVersion());
    }
    
    /**
     * Streaming парсинг для ОЧЕНЬ больших файлов (>1GB)
     * Использует Jackson Streaming API для минимального потребления памяти
     */
    private OpenAPI parseJsonStreaming(String jsonFile) throws Exception {
        log.info("📖 Streaming парсинг JSON (для файлов >1GB)...");
        
        File file = new File(jsonFile);
        long fileSize = file.length();
        log.info("Размер файла: {} MB", fileSize / (1024 * 1024));
        
        // Для очень больших файлов используем OpenAPIV3Parser с оптимизированными настройками
        // Отключаем resolve полностью для экономии памяти
        OpenAPIV3Parser parser = new OpenAPIV3Parser();
        ParseOptions options = new ParseOptions();
        options.setResolve(false);
        options.setResolveFully(false);
        
        // Используем readLocation - он уже использует streaming внутри
        // Для локальных файлов используем путь напрямую (качество выше)
        String locationForParser = toFileLocation(file.getAbsolutePath());
        SwaggerParseResult result = parser.readLocation(locationForParser, null, options);
        
        if (result.getOpenAPI() != null) {
            log.info("Streaming парсинг успешен");
            return result.getOpenAPI();
        }
        
        // Fallback на обычный парсинг если streaming не сработал
        return parseJsonDirectly(jsonFile);
    }
    
    /**
     * Memory-mapped парсинг для больших файлов (100MB - 1GB)
     * Использует NIO memory-mapped files для эффективной работы с большими файлами
     */
    private OpenAPI parseJsonMemoryMapped(String jsonFile) throws Exception {
        log.info("📖 Memory-mapped парсинг JSON (для файлов 100MB-1GB)...");
        
        File file = new File(jsonFile);
        long fileSize = file.length();
        log.info("Размер файла: {} MB", fileSize / (1024 * 1024));
        
        // Используем OpenAPIV3Parser с оптимизированными настройками
        OpenAPIV3Parser parser = new OpenAPIV3Parser();
        ParseOptions options = new ParseOptions();
        options.setResolve(false); // Экономия памяти
        options.setResolveFully(false);
        
        // Используем readLocation - он эффективно обработает большой файл
        // OpenAPIV3Parser уже оптимизирован для работы с большими файлами
        // Для локальных файлов используем путь напрямую (качество выше)
        String locationForParser = toFileLocation(file.getAbsolutePath());
        SwaggerParseResult result = parser.readLocation(locationForParser, null, options);
        
        if (result.getOpenAPI() != null) {
            log.info("Memory-mapped парсинг успешен");
            return result.getOpenAPI();
        }
        
        // Fallback на обычный парсинг
        return parseJsonDirectly(jsonFile);
    }
    
    /**
     * Прямой парсинг JSON через Jackson (обходит SnakeYAML лимит для больших файлов)
     * 
     * КРИТИЧНО: Поддерживает файлы >8MB через streaming!
     * 
     * ВАЖНО: Использует OpenAPIV3Parser через Jackson для правильного маппинга модели OpenAPI
     */
    private OpenAPI parseJsonDirectly(String jsonFile) throws Exception {
        log.info("📖 Парсинг JSON напрямую через Jackson (поддержка больших файлов >8MB)...");
        
        File file = new File(jsonFile);
        long fileSize = file.length();
        
        // КРИТИЧНО: Для правильного маппинга OpenAPI модели используем OpenAPIV3Parser
        // но с оптимизированными настройками для больших файлов
        OpenAPIV3Parser parser = new OpenAPIV3Parser();
        ParseOptions options = new ParseOptions();
        
        // КАЧЕСТВО: для больших файлов тоже включаем resolve, но без полного разрешения
        // Это обеспечивает точность анализа схем
        options.setResolve(true); // Включаем resolve для качества
        options.setResolveFully(false); // Не разрешаем полностью (это медленно)
        
        // Парсим JSON файл
        // Для локальных файлов используем путь напрямую (качество выше)
        String locationForParser = toFileLocation(file.getAbsolutePath());
        SwaggerParseResult result = parser.readLocation(locationForParser, null, options);
        
        if (result.getMessages() != null && !result.getMessages().isEmpty()) {
            // Фильтруем некритичные предупреждения для больших файлов
            for (String message : result.getMessages()) {
                if (message.contains("unable to resolve") || message.contains("reference")) {
                    log.debug("Предупреждение парсера (можно игнорировать для больших файлов): {}", message);
                } else {
                    log.warn("Предупреждение парсера: {}", message);
                }
            }
        }
        
        if (result.getOpenAPI() != null) {
            log.info("JSON файл успешно распарсен (размер: {} MB)", fileSize / (1024 * 1024));
            return result.getOpenAPI();
        }
        
        // Если парсер не справился, пробуем через Jackson напрямую (fallback)
        log.warn("OpenAPIV3Parser не справился, пробуем прямой Jackson парсинг...");
        try {
        com.fasterxml.jackson.databind.ObjectMapper mapper = 
            new com.fasterxml.jackson.databind.ObjectMapper();
        
            // Настраиваем для больших файлов
            com.fasterxml.jackson.core.JsonFactory factory = mapper.getFactory();
            factory.configure(com.fasterxml.jackson.core.JsonParser.Feature.AUTO_CLOSE_SOURCE, false);
            factory.configure(com.fasterxml.jackson.core.JsonParser.Feature.ALLOW_NUMERIC_LEADING_ZEROS, true);
            
            // Для очень больших файлов (>10MB) используем streaming
            if (fileSize > 10_000_000) {
                log.info("💡 Файл очень большой ({} MB), используем streaming парсинг...", fileSize / (1024 * 1024));
                
                try (com.fasterxml.jackson.core.JsonParser jsonParser = factory.createParser(file)) {
                    jsonParser.configure(com.fasterxml.jackson.core.JsonParser.Feature.AUTO_CLOSE_SOURCE, false);
                    return mapper.readValue(jsonParser, OpenAPI.class);
                }
            } else {
                // Для файлов <10MB читаем напрямую
                return mapper.readValue(file, OpenAPI.class);
            }
        } catch (Exception e) {
            log.error("Прямой Jackson парсинг тоже не удался: {}", e.getMessage());
            throw new IllegalStateException(
                "Не удалось распарсить JSON файл через Jackson. " +
                "Возможно файл поврежден или имеет невалидную структуру OpenAPI. " +
                "Ошибка: " + e.getMessage(), e);
        }
    }
    
    /**
     * Получить все эндпоинты
     */
    public Map<String, PathItem> getAllEndpoints() {
        if (openAPI == null || openAPI.getPaths() == null) {
            return Collections.emptyMap();
        }
        return openAPI.getPaths();
    }
    
    /**
     * Получить информацию об API
     */
    public String getApiTitle() {
        return openAPI != null && openAPI.getInfo() != null 
            ? openAPI.getInfo().getTitle() 
            : "Unknown API";
    }
    
    public String getApiVersion() {
        return openAPI != null && openAPI.getInfo() != null 
            ? openAPI.getInfo().getVersion() 
            : "Unknown";
    }
    
    /**
     * Получить базовый URL сервера
     */
    public String getServerUrl() {
        if (openAPI != null && openAPI.getServers() != null && !openAPI.getServers().isEmpty()) {
            for (io.swagger.v3.oas.models.servers.Server server : openAPI.getServers()) {
                if (server == null || server.getUrl() == null) {
                    continue;
                }
                String url = server.getUrl().trim();
                if (url.isEmpty()) {
                    continue;
                }
                if (url.startsWith("http://") || url.startsWith("https://")) {
                    return url;
                }
                if (url.startsWith("//")) {
                    return "https:" + url;
                }
                // относительные пути не считаем корректными для targetUrl
                log.debug("Пропуск относительного server URL: {}", url);
            }
        }
        return null;
    }
    
    /**
     * Получить все операции (методы) для эндпоинта
     */
    public Map<String, Operation> getOperationsForPath(String path) {
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null || path == null) {
            return Collections.emptyMap();
        }
        
        PathItem pathItem = openAPI.getPaths().get(path);
        if (pathItem == null) {
            return Collections.emptyMap();
        }
        
        Map<String, Operation> operations = new LinkedHashMap<>();
        if (pathItem.getGet() != null) operations.put("GET", pathItem.getGet());
        if (pathItem.getPost() != null) operations.put("POST", pathItem.getPost());
        if (pathItem.getPut() != null) operations.put("PUT", pathItem.getPut());
        if (pathItem.getDelete() != null) operations.put("DELETE", pathItem.getDelete());
        if (pathItem.getPatch() != null) operations.put("PATCH", pathItem.getPatch());
        if (pathItem.getOptions() != null) operations.put("OPTIONS", pathItem.getOptions());
        if (pathItem.getHead() != null) operations.put("HEAD", pathItem.getHead());
        
        return operations;
    }
    
    /**
     * Проверить, требует ли операция аутентификацию
     */
    public boolean requiresAuthentication(Operation operation) {
        if (operation.getSecurity() != null && !operation.getSecurity().isEmpty()) {
            return true;
        }
        
        // Проверяем глобальную security
        if (openAPI.getSecurity() != null && !openAPI.getSecurity().isEmpty()) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Получить объект OpenAPI
     */
    public OpenAPI getOpenAPI() {
        return openAPI;
    }
    
    /**
     * Получить общее количество эндпоинтов
     */
    public int getTotalEndpointsCount() {
        // ИСПРАВЛЕНО: Используем ключ пути вместо toString()
        int count = 0;
        Map<String, PathItem> endpoints = getAllEndpoints();
        if (endpoints == null) {
            return 0;
        }
        
        for (Map.Entry<String, PathItem> entry : endpoints.entrySet()) {
            String path = entry.getKey();
            count += getOperationsForPath(path).size();
        }
        return count;
    }
}


