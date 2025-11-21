package com.vtb.scanner.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import lombok.Data;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Конфигурация сканера из YAML файла
 * Убирает хардкод из сканеров
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
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
    private FeatureToggles featureToggles;
    private RiskWeights riskWeights;
    private SecretInventory secretInventory;
    private SmartFuzzerSettings smartFuzzer;
    private AccessControl accessControl;
    private DynamicScanner dynamicScanner;
    
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
                if (instance.featureToggles == null) {
                    instance.featureToggles = new FeatureToggles();
                }
                if (instance.riskWeights == null) {
                    instance.riskWeights = new RiskWeights();
                }
                instance.riskWeights.ensureDefaults();
                if (instance.secretInventory == null) {
                    instance.secretInventory = new SecretInventory();
                }
                if (instance.smartFuzzer == null) {
                    instance.smartFuzzer = new SmartFuzzerSettings();
                }
                instance.smartFuzzer.ensureDefaults();
                if (instance.accessControl == null) {
                    instance.accessControl = new AccessControl();
                }
                if (instance.dynamicScanner == null) {
                    instance.dynamicScanner = new DynamicScanner();
                }
                instance.dynamicScanner.ensureDefaults();
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

    @Data
    public static class FeatureToggles {
        private Boolean enableMarketplaceHeuristics = Boolean.TRUE;
        private Boolean enableGovernmentHeuristics = Boolean.TRUE;
        private Boolean enableConsentChecks = Boolean.TRUE;
        private Boolean enableSessionHardening = Boolean.TRUE;
        private Boolean enableLoginRateLimitCheck = Boolean.TRUE;
        private Boolean enableFraudHeuristics = Boolean.TRUE;

        public boolean marketplaceEnabled() {
            return enableMarketplaceHeuristics == null || enableMarketplaceHeuristics;
        }

        public boolean governmentEnabled() {
            return enableGovernmentHeuristics == null || enableGovernmentHeuristics;
        }

        public boolean consentEnabled() {
            return enableConsentChecks == null || enableConsentChecks;
        }

        public boolean sessionHardeningEnabled() {
            return enableSessionHardening == null || enableSessionHardening;
        }

        public boolean loginRateLimitEnabled() {
            return enableLoginRateLimitCheck == null || enableLoginRateLimitCheck;
        }

        public boolean fraudHeuristicsEnabled() {
            return enableFraudHeuristics == null || enableFraudHeuristics;
        }
    }

    @Data
    public static class RiskWeights {
        private Integer marketplaceFlow;
        private Integer marketplaceFlowHighContext;
        private Integer governmentFlow;
        private Integer sessionFlow;
        private Integer consentPresent;
        private Integer consentMissing;
        private Integer consentMissingHighContext;
        private Integer loginAbuse;
        private Map<String, Double> contextMultipliers;

        private void ensureDefaults() {
            if (contextMultipliers == null) {
                contextMultipliers = new java.util.HashMap<>();
            }
            contextMultipliers.putIfAbsent("banking", 1.0);
            contextMultipliers.putIfAbsent("government", 1.0);
            contextMultipliers.putIfAbsent("healthcare", 1.0);
        }
    }

    @Data
    public static class SecretInventory {
        private List<String> shadowEnvironmentKeywords;
        private List<String> secretPatterns;
        private List<String> secretIndicators;
    }

    @Data
    public static class AccessControl {
        private List<String> accessTextMarkers;
        private List<String> headerNames;
        private List<String> queryNames;
        private List<String> bodyPropertyNames;
        private List<String> consentMarkers;
        private List<String> openBankingPathMarkers;
        private List<String> openBankingTextMarkers;
        private List<String> strongAuthTextMarkers;
        private List<String> strongAuthHeaderNames;
    }

    @Data
    public static class SmartFuzzerSettings {
        private static final int DEFAULT_GLOBAL_LIMIT = 20;
        private static final int DEFAULT_PER_ENDPOINT_LIMIT = 4;
        private static final long DEFAULT_DELAY_MS = 150L;
        private static final int DEFAULT_TIMEOUT_SEC = 4;
        private static final int DEFAULT_MAX_TIMEOUTS_PER_ENDPOINT = 2;
        private static final int DEFAULT_MAX_TOTAL_TIMEOUTS = 5;
        private static final int DEFAULT_MAX_NETWORK_ERRORS = 3;
        private static final int DEFAULT_MAX_NETWORK_ERRORS_PER_ENDPOINT = 2;
        private static final List<Integer> DEFAULT_STOP_STATUS_CODES = List.of(401, 403, 429);

        private Integer globalLimit;
        private Integer perEndpointLimit;
        private Long delayMs;
        private Integer timeoutSec;
        private Integer maxTimeoutsPerEndpoint;
        private Integer maxTotalTimeouts;
        private Integer maxNetworkErrors;
        private Integer maxNetworkErrorsPerEndpoint;
        private List<Integer> stopStatusCodes;
        private Map<String, ContextSettings> contexts;

        public void ensureDefaults() {
            if (globalLimit == null || globalLimit <= 0) {
                globalLimit = DEFAULT_GLOBAL_LIMIT;
            }
            if (perEndpointLimit == null || perEndpointLimit <= 0) {
                perEndpointLimit = DEFAULT_PER_ENDPOINT_LIMIT;
            }
            if (delayMs == null || delayMs < 0) {
                delayMs = DEFAULT_DELAY_MS;
            }
            if (timeoutSec == null || timeoutSec <= 0) {
                timeoutSec = DEFAULT_TIMEOUT_SEC;
            }
            if (maxTimeoutsPerEndpoint == null || maxTimeoutsPerEndpoint < 1) {
                maxTimeoutsPerEndpoint = DEFAULT_MAX_TIMEOUTS_PER_ENDPOINT;
            }
            if (maxTotalTimeouts == null || maxTotalTimeouts < 1) {
                maxTotalTimeouts = DEFAULT_MAX_TOTAL_TIMEOUTS;
            }
            if (maxNetworkErrors == null || maxNetworkErrors < 1) {
                maxNetworkErrors = DEFAULT_MAX_NETWORK_ERRORS;
            }
            if (maxNetworkErrorsPerEndpoint == null || maxNetworkErrorsPerEndpoint < 1) {
                maxNetworkErrorsPerEndpoint = DEFAULT_MAX_NETWORK_ERRORS_PER_ENDPOINT;
            }
            if (stopStatusCodes == null || stopStatusCodes.isEmpty()) {
                stopStatusCodes = new ArrayList<>(DEFAULT_STOP_STATUS_CODES);
            } else {
                stopStatusCodes = new ArrayList<>(stopStatusCodes);
            }

            if (contexts != null) {
                contexts.replaceAll((key, value) -> {
                    if (value == null) {
                        value = new ContextSettings();
                    }
                    value.ensureDefaults();
                    return value;
                });
            }
        }

        public ContextSettings resolveContext(String contextName) {
            ContextSettings effective = new ContextSettings();
            effective.setGlobalLimit(globalLimit);
            effective.setPerEndpointLimit(perEndpointLimit);
            effective.setDelayMs(delayMs);
            effective.setTimeoutSec(timeoutSec);
            effective.setMaxTimeoutsPerEndpoint(maxTimeoutsPerEndpoint);
            effective.setMaxTotalTimeouts(maxTotalTimeouts);
            effective.setMaxNetworkErrors(maxNetworkErrors);
            effective.setMaxNetworkErrorsPerEndpoint(maxNetworkErrorsPerEndpoint);
            effective.setStopStatusCodes(new ArrayList<>(stopStatusCodes));

            if (contexts != null && !contexts.isEmpty()) {
                ContextSettings override = lookupContext(contextName);
                if (override != null) {
                    effective.applyOverride(override);
                }
            }
            return effective;
        }

        private ContextSettings lookupContext(String contextName) {
            if (contextName == null || contexts == null) {
                return null;
            }
            ContextSettings exact = contexts.get(contextName);
            if (exact != null) {
                return exact;
            }
            ContextSettings upper = contexts.get(contextName.toUpperCase(Locale.ROOT));
            if (upper != null) {
                return upper;
            }
            return contexts.get(contextName.toLowerCase(Locale.ROOT));
        }

        @Data
        public static class ContextSettings {
            private Integer globalLimit;
            private Integer perEndpointLimit;
            private Long delayMs;
            private Integer timeoutSec;
            private Integer maxTimeoutsPerEndpoint;
            private Integer maxTotalTimeouts;
            private Integer maxNetworkErrors;
            private Integer maxNetworkErrorsPerEndpoint;
            private List<Integer> stopStatusCodes;

            void ensureDefaults() {
                if (stopStatusCodes != null && stopStatusCodes.isEmpty()) {
                    stopStatusCodes = null;
                }
            }

            void applyOverride(ContextSettings override) {
                if (override == null) {
                    return;
                }
                if (override.getGlobalLimit() != null && override.getGlobalLimit() > 0) {
                    this.globalLimit = override.getGlobalLimit();
                }
                if (override.getPerEndpointLimit() != null && override.getPerEndpointLimit() > 0) {
                    this.perEndpointLimit = override.getPerEndpointLimit();
                }
                if (override.getDelayMs() != null && override.getDelayMs() >= 0) {
                    this.delayMs = override.getDelayMs();
                }
                if (override.getTimeoutSec() != null && override.getTimeoutSec() > 0) {
                    this.timeoutSec = override.getTimeoutSec();
                }
                if (override.getMaxTimeoutsPerEndpoint() != null && override.getMaxTimeoutsPerEndpoint() > 0) {
                    this.maxTimeoutsPerEndpoint = override.getMaxTimeoutsPerEndpoint();
                }
                if (override.getMaxTotalTimeouts() != null && override.getMaxTotalTimeouts() > 0) {
                    this.maxTotalTimeouts = override.getMaxTotalTimeouts();
                }
                if (override.getMaxNetworkErrors() != null && override.getMaxNetworkErrors() > 0) {
                    this.maxNetworkErrors = override.getMaxNetworkErrors();
                }
                if (override.getMaxNetworkErrorsPerEndpoint() != null && override.getMaxNetworkErrorsPerEndpoint() > 0) {
                    this.maxNetworkErrorsPerEndpoint = override.getMaxNetworkErrorsPerEndpoint();
                }
                if (override.getStopStatusCodes() != null && !override.getStopStatusCodes().isEmpty()) {
                    this.stopStatusCodes = new ArrayList<>(override.getStopStatusCodes());
                }
            }
        }
    }

    @Data
    public static class DynamicScanner {
        private Boolean enabled;
        private Integer maxScenarios;
        private Integer maxStepsPerScenario;
        private Long delayMs;
        private Integer timeoutSec;
        private Integer maxRequestsPerSecond;

        public void ensureDefaults() {
            if (enabled == null) {
                enabled = Boolean.TRUE;
            }
            if (maxScenarios == null || maxScenarios <= 0) {
                maxScenarios = 5;
            }
            if (maxStepsPerScenario == null || maxStepsPerScenario <= 0) {
                maxStepsPerScenario = 3;
            }
            if (delayMs == null || delayMs < 0) {
                delayMs = 150L;
            }
            if (timeoutSec == null || timeoutSec <= 0) {
                timeoutSec = 4;
            }
            if (maxRequestsPerSecond == null || maxRequestsPerSecond <= 0) {
                maxRequestsPerSecond = 1;
            }
        }

        public boolean isEnabled() {
            return Boolean.TRUE.equals(enabled);
        }
    }
}

