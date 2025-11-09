package com.vtb.scanner.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import lombok.Data;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Конфигурация сканера из YAML файла
 * Убирает хардкод из сканеров
 */
@Data
public class ScannerConfig {
    
    private Patterns patterns;
    private Map<String, List<String>> sensitivePaths;
    private List<String> personalDataFields;
    private GostAlgorithms gostAlgorithms;
    private List<String> internationalAlgorithms;
    private Map<String, String> severityRules;
    private Map<String, List<String>> sensitiveOperations;
    private List<String> protectionKeywords;
    private List<String> sensitiveResponseFields;
    private List<String> readonlyFields;
    
    @Data
    public static class Patterns {
        private List<String> idParameters;
        private List<String> sqlParameters;
        private List<String> cmdParameters;
        private List<String> nosqlParameters;
        private List<String> ssrfParameters;
    }
    
    @Data
    public static class GostAlgorithms {
        private List<String> signatures;
        private List<String> hashes;
        private List<String> ciphers;
    }
    
    private static ScannerConfig instance;
    
    /**
     * Загрузить конфигурацию из classpath
     */
    public static ScannerConfig load() {
        if (instance == null) {
            InputStream is = null;
            try {
                ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
                is = ScannerConfig.class.getClassLoader()
                    .getResourceAsStream("scanner-config.yaml");
                
                if (is == null) {
                    throw new IllegalStateException("scanner-config.yaml не найден в classpath");
                }
                
                instance = mapper.readValue(is, ScannerConfig.class);
                
            } catch (Exception e) {
                throw new RuntimeException("Ошибка загрузки конфигурации: " + e.getMessage(), e);
            } finally {
                // КРИТИЧНО: Закрываем InputStream для предотвращения утечки ресурсов
                if (is != null) {
                    try {
                        is.close();
                    } catch (Exception e) {
                        // Игнорируем ошибки закрытия, но логируем
                        System.err.println("Предупреждение: не удалось закрыть InputStream: " + e.getMessage());
                    }
                }
            }
        }
        return instance;
    }
    
    /**
     * Получить все ГОСТ алгоритмы в один список
     */
    public Set<String> getAllGostAlgorithms() {
        Set<String> all = new java.util.HashSet<>();
        if (gostAlgorithms != null) {
            if (gostAlgorithms.getSignatures() != null) all.addAll(gostAlgorithms.getSignatures());
            if (gostAlgorithms.getHashes() != null) all.addAll(gostAlgorithms.getHashes());
            if (gostAlgorithms.getCiphers() != null) all.addAll(gostAlgorithms.getCiphers());
        }
        return all;
    }
}

