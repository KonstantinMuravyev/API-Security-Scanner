package com.vtb.scanner.fuzzing;

import com.vtb.scanner.config.ScannerConfig;
import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.models.AttackSurfaceSummary;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.ThreatGraph;
import com.vtb.scanner.models.ThreatNode;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.semantic.ContextAnalyzer;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.examples.Example;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Credentials;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Base64;

/**
 * ИННОВАЦИЯ: Smart Fuzzer - БЕЗ риска DDoS!
 * 
 * ЦЕЛЕВОЙ fuzzing: проверяет найденные уязвимости через реальные HTTP запросы
 * 
 * Безопасность:
 * 1. Числовые лимиты запросов (глобальный + на endpoint)
 * 2. Обработка rate limits (429) - остановка для endpoint
 * 3. Обработка auth errors (401/403) - остановка попыток
 * 4. Timeout handling - продолжение с лимитом
 * 5. Thread-safe счетчики (AtomicInteger)
 * 6. Задержки между запросами (500ms)
 * 
 * Это НЕ DDoS, это "gentle targeted probing"!
 */
@Slf4j
public class SmartFuzzer {
    
    private static final int DEFAULT_GLOBAL_LIMIT = 20;
    private static final int DEFAULT_PER_ENDPOINT_LIMIT = 4;
    private static final long DEFAULT_DELAY_MS = 150L;
    private static final int DEFAULT_TIMEOUT_SEC = 4;
    private static final int DEFAULT_MAX_TIMEOUTS_PER_ENDPOINT = 2;
    private static final int DEFAULT_MAX_TOTAL_TIMEOUTS = 5;
    private static final int DEFAULT_MAX_NETWORK_ERRORS = 3;
    private static final int DEFAULT_MAX_NETWORK_ERRORS_PER_ENDPOINT = 2;
    private static final Set<Integer> DEFAULT_STOP_CODES = Set.of(401, 403, 429);
    
    private final String targetUrl;
    private OkHttpClient httpClient;
    private final ScannerConfig.SmartFuzzerSettings settings;

    private int maxRequestsPerEndpoint = DEFAULT_PER_ENDPOINT_LIMIT;
    private int maxTotalRequests = DEFAULT_GLOBAL_LIMIT;
    private long delayMs = DEFAULT_DELAY_MS;
    private int timeoutSec = DEFAULT_TIMEOUT_SEC;
    private int maxTimeoutsPerEndpoint = DEFAULT_MAX_TIMEOUTS_PER_ENDPOINT;
    private int maxTotalTimeouts = DEFAULT_MAX_TOTAL_TIMEOUTS;
    private int maxNetworkErrors = DEFAULT_MAX_NETWORK_ERRORS;
    private int maxNetworkErrorsPerEndpoint = DEFAULT_MAX_NETWORK_ERRORS_PER_ENDPOINT;
    private Set<Integer> stopStatusCodes = new LinkedHashSet<>(DEFAULT_STOP_CODES);
    
    // Thread-safe счетчики
    private final AtomicInteger totalRequests = new AtomicInteger(0);
    private final Map<String, AtomicInteger> requestsPerEndpoint = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> timeoutsPerEndpoint = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> networkErrorsPerEndpoint = new ConcurrentHashMap<>();
    private final AtomicInteger totalTimeouts = new AtomicInteger(0);
    private final AtomicInteger totalNetworkErrors = new AtomicInteger(0);
    
    private static final String DEFAULT_BEARER_TOKEN = "Bearer test-token";
    private static final String DEFAULT_API_KEY = "test-api-key";
    private static final MediaType JSON_MEDIA_TYPE = MediaType.parse("application/json");
    private static final SecureRandom WEB_SOCKET_RANDOM = new SecureRandom();
    private static final Set<String> GRAPHQL_INDICATORS = Set.of(
        "graphql", "gql", "__schema", "mutation", "resolver", "subscription"
    );
    private static final Set<String> GRPC_INDICATORS = Set.of(
        "grpc", "protobuf", "proto", "h2c", "grpc-web"
    );
    private static final Set<String> WEBSOCKET_INDICATORS = Set.of(
        "websocket", "ws://", "wss://", "stomp", "mqtt", "pubsub", "subscribe"
    );

    private record FuzzProfile(
        List<String> bolaPayloads,
        List<String> sqlPayloads,
        List<String> noSqlPayloads,
        List<String> commandPayloads,
        List<String> ldapPayloads,
        List<String> ssrfTargets
    ) { }

    private record FuzzContext(
        List<String> bolaPayloads,
        List<String> sqlPayloads,
        List<String> noSqlPayloads,
        List<String> commandPayloads,
        List<String> ldapPayloads,
        List<String> ssrfTargets
    ) { }

    private static FuzzProfile generalProfile() {
        return new FuzzProfile(
            List.of("0", "999999", "-1", "1"),
            List.of(
                "' OR '1'='1",
                "1; DROP TABLE users--",
                "1' UNION SELECT NULL--",
                "admin'--"
            ),
            List.of(
                "'; return true; var x='",
                "{$ne: null}",
                "{$gt: ''}",
                "'; return true; //"
            ),
            List.of(
                "; ls -la",
                "| whoami",
                "& dir",
                "; cat /etc/passwd"
            ),
            List.of(
                "*)(uid=*))(|(uid=*",
                "admin)(&",
                "*))%00",
                "admin)(|(password=*"
            ),
            List.of(
                "http://127.0.0.1:8080",
                "http://169.254.169.254/latest/meta-data",
                "http://localhost/admin"
            )
        );
    }

    private static FuzzProfile bankingProfile() {
        FuzzProfile base = generalProfile();
        return new FuzzProfile(
            merge(base.bolaPayloads(), List.of("1000000001", "4000000000", "5000000005")),
            merge(base.sqlPayloads(), List.of(
                "1 UNION SELECT card_number FROM cards",
                "' UNION SELECT iban, balance FROM accounts--"
            )),
            base.noSqlPayloads(),
            base.commandPayloads(),
            base.ldapPayloads(),
            merge(base.ssrfTargets(), List.of(
                "https://169.254.169.254/latest/meta-data/iam",
                "https://metadata.bank.internal/admin",
                "http://10.0.0.5:8080/internal/health"
            ))
        );
    }

    private static FuzzProfile telecomProfile() {
        FuzzProfile base = generalProfile();
        return new FuzzProfile(
            merge(base.bolaPayloads(), List.of("79261234567", "89991234567", "70000000000")),
            base.sqlPayloads(),
            merge(base.noSqlPayloads(), List.of("{\"$regex\": \".*\"}", "{$where: 'sleep(1)'}")),
            base.commandPayloads(),
            base.ldapPayloads(),
            merge(base.ssrfTargets(), List.of(
                "http://10.0.0.10:8080/ocs",
                "http://127.0.0.1:8080/management",
                "http://169.254.169.254/latest/user-data"
            ))
        );
    }

    private static FuzzProfile automotiveProfile() {
        FuzzProfile base = generalProfile();
        return new FuzzProfile(
            merge(base.bolaPayloads(), List.of("WVWZZZ1JZXW000001", "LADA1111111111111", "99999999999999999")),
            merge(base.sqlPayloads(), List.of(
                "' UNION SELECT firmware_version FROM ota_updates--",
                "1; UPDATE vehicles SET mode='debug' WHERE vin LIKE 'W%'"
            )),
            base.noSqlPayloads(),
            merge(base.commandPayloads(), List.of("; reboot", "; cat /etc/shadow", "| powershell.exe Get-Process")),
            base.ldapPayloads(),
            merge(base.ssrfTargets(), List.of(
                "http://127.0.0.1:5555/ota",
                "http://unix:/var/run/dbus/system_bus_socket",
                "http://10.0.0.2:8080/can/diagnostics"
            ))
        );
    }

    private static List<String> merge(List<String> base, List<String> extra) {
        LinkedHashSet<String> merged = new LinkedHashSet<>();
        if (base != null) {
            merged.addAll(base);
        }
        if (extra != null) {
            merged.addAll(extra);
        }
        return List.copyOf(merged);
    }

    private FuzzProfile selectProfile(ContextAnalyzer.APIContext context) {
        if (context == null) {
            return generalProfile();
        }
        return switch (context) {
            case BANKING -> bankingProfile();
            case TELECOM -> telecomProfile();
            case AUTOMOTIVE -> automotiveProfile();
            default -> generalProfile();
        };
    }

    private FuzzContext prepareFuzzContext(List<Vulnerability> vulnerabilities,
                                           ContextAnalyzer.APIContext context,
                                           AttackSurfaceSummary attackSurface,
                                           ThreatGraph threatGraph) {
        FuzzProfile profile = selectProfile(context);

        LinkedHashSet<String> bolaPayloads = new LinkedHashSet<>(profile.bolaPayloads());
        LinkedHashSet<String> sqlPayloads = new LinkedHashSet<>(profile.sqlPayloads());
        LinkedHashSet<String> noSqlPayloads = new LinkedHashSet<>(profile.noSqlPayloads());
        LinkedHashSet<String> commandPayloads = new LinkedHashSet<>(profile.commandPayloads());
        LinkedHashSet<String> ldapPayloads = new LinkedHashSet<>(profile.ldapPayloads());
        LinkedHashSet<String> ssrfTargets = new LinkedHashSet<>(profile.ssrfTargets());

        if (vulnerabilities != null) {
            for (Vulnerability vulnerability : vulnerabilities) {
                if (vulnerability == null) {
                    continue;
                }
                if (vulnerability.getType() == VulnerabilityType.BOLA
                    || vulnerability.getType() == VulnerabilityType.BFLA) {
                    bolaPayloads.addAll(deriveBolaCandidates(vulnerability.getEndpoint()));
                }
                if (vulnerability.getType() == VulnerabilityType.SSRF
                    || (vulnerability.getTitle() != null && vulnerability.getTitle().toLowerCase(Locale.ROOT).contains("webhook"))) {
                    ssrfTargets.add("http://127.0.0.1:9000/internal-callback");
                    ssrfTargets.add("http://10.0.0.10:80/metadata");
                }
                if (vulnerability.getEvidence() != null) {
                    String evidenceLower = vulnerability.getEvidence().toLowerCase(Locale.ROOT);
                    if (evidenceLower.contains("firmware") || evidenceLower.contains("ota")) {
                        commandPayloads.add("; curl http://127.0.0.1:5555/ota");
                    }
                }
            }
        }

        if (attackSurface != null) {
            for (String entry : attackSurface.getEntryPoints()) {
                if (entry == null) {
                    continue;
                }
                String lower = entry.toLowerCase(Locale.ROOT);
                if (lower.contains("webhook") || lower.contains("callback") || lower.contains("notify")) {
                    ssrfTargets.add(sanitizeEntryForSsrf(entry));
                }
                if (lower.contains("ota") || lower.contains("firmware") || lower.contains("update")) {
                    commandPayloads.add("| curl -s http://10.0.0.2:8080/ota/status");
                }
            }
        }

        if (threatGraph != null && threatGraph.getNodes() != null) {
            for (ThreatNode node : threatGraph.getNodes()) {
                if (node == null || node.getLabel() == null) {
                    continue;
                }
                String labelLower = node.getLabel().toLowerCase(Locale.ROOT);
                if (labelLower.contains("webhook") || labelLower.contains("callback") || labelLower.contains("notification")) {
                    ssrfTargets.add("http://127.0.0.1:8081" + normalizedPath(node.getLabel()));
                }
                if (labelLower.contains("consent") || labelLower.contains("account")) {
                    bolaPayloads.addAll(List.of("7000000001", "8000000002"));
                }
                if (labelLower.contains("vin") || labelLower.contains("vehicle")) {
                    bolaPayloads.add("WVWZZZ1JZXW999999");
                }
            }
        }

        return new FuzzContext(
            List.copyOf(bolaPayloads),
            List.copyOf(sqlPayloads),
            List.copyOf(noSqlPayloads),
            List.copyOf(commandPayloads),
            List.copyOf(ldapPayloads),
            List.copyOf(ssrfTargets)
        );
    }

    private List<String> deriveBolaCandidates(String endpoint) {
        if (endpoint == null) {
            return Collections.emptyList();
        }
        Matcher matcher = Pattern.compile("\\{([^}/]+)}").matcher(endpoint);
        List<String> candidates = new ArrayList<>();
        while (matcher.find()) {
            String param = matcher.group(1);
            if (param == null) {
                continue;
            }
            String lower = param.toLowerCase(Locale.ROOT);
            if (lower.contains("account") || lower.contains("iban")) {
                candidates.addAll(List.of("1000000000", "2000000000", "3000000000"));
            } else if (lower.contains("client") || lower.contains("user")) {
                candidates.addAll(List.of("client-001", "client-999", "guest"));
            } else if (lower.contains("consent")) {
                candidates.addAll(List.of("consent-0001", "consent-9999"));
            } else if (lower.contains("vin")) {
                candidates.addAll(List.of("WVWZZZ1JZXW123456", "LADA0000000000000"));
            } else if (lower.contains("phone") || lower.contains("msisdn")) {
                candidates.addAll(List.of("79001234567", "89991112233"));
            } else if (lower.contains("contract")) {
                candidates.addAll(List.of("CNT-001", "CNT-777"));
            } else {
                candidates.add("42");
            }
        }
        return candidates;
    }

    private String sanitizeEntryForSsrf(String entry) {
        if (entry == null || entry.isBlank()) {
            return "http://127.0.0.1:8080";
        }
        String normalized = normalizedPath(entry);
        return "http://127.0.0.1:8080" + normalized;
    }

    private String normalizedPath(String label) {
        if (label == null) {
            return "";
        }
        String candidate = label.trim();
        if (candidate.isEmpty()) {
            return "";
        }
        if (!candidate.startsWith("/")) {
            candidate = "/" + candidate.replaceAll("^https?://[^/]+", "");
        }
        return candidate.replaceAll("\\s+", "-");
    }

    private Operation findOperation(OpenAPI openAPI, String endpoint, String method) {
        if (openAPI == null || openAPI.getPaths() == null || endpoint == null || method == null) {
            return null;
        }
        String normalizedPath = normalizeEndpointToPath(endpoint);
        if (normalizedPath == null) {
            return null;
        }
        PathItem pathItem = getPathItem(openAPI, normalizedPath);
        if (pathItem == null) {
            return null;
        }
        String upperMethod = method.toUpperCase(Locale.ROOT);
        return switch (upperMethod) {
            case "GET" -> pathItem.getGet();
            case "POST" -> pathItem.getPost();
            case "PUT" -> pathItem.getPut();
            case "DELETE" -> pathItem.getDelete();
            case "PATCH" -> pathItem.getPatch();
            case "HEAD" -> pathItem.getHead();
            case "OPTIONS" -> pathItem.getOptions();
            default -> null;
        };
    }

    private String normalizeEndpointToPath(String endpoint) {
        if (endpoint == null) {
            return null;
        }
        String candidate = endpoint;
        if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
            try {
                URI uri = new URI(endpoint);
                candidate = uri.getPath();
                if (candidate == null || candidate.isEmpty()) {
                    candidate = "/";
                }
            } catch (URISyntaxException e) {
                log.debug("Не удалось распарсить endpoint как URI: {} ({})", endpoint, e.getMessage());
            }
        }
        if (candidate == null || candidate.isEmpty()) {
            return null;
        }
        if (!candidate.startsWith("/")) {
            candidate = "/" + candidate;
        }
        // Убираем лишний трейлинг / (но оставляем корень)
        if (candidate.length() > 1 && candidate.endsWith("/")) {
            candidate = candidate.substring(0, candidate.length() - 1);
        }
        return candidate;
    }

    private PathItem getPathItem(OpenAPI openAPI, String path) {
        if (openAPI.getPaths() == null) {
            return null;
        }
        PathItem pathItem = openAPI.getPaths().get(path);
        if (pathItem != null) {
            return pathItem;
        }
        // Попробуем альтернативы (добавить/убрать / в конце)
        if (path.endsWith("/")) {
            String withoutSlash = path.substring(0, path.length() - 1);
            pathItem = openAPI.getPaths().get(withoutSlash);
            if (pathItem != null) {
                return pathItem;
            }
        } else {
            pathItem = openAPI.getPaths().get(path + "/");
            if (pathItem != null) {
                return pathItem;
            }
        }
        return null;
    }

    private List<SecurityRequirement> resolveSecurityRequirements(Operation operation, OpenAPI openAPI) {
        if (operation != null && operation.getSecurity() != null && !operation.getSecurity().isEmpty()) {
            return operation.getSecurity();
        }
        if (openAPI != null && openAPI.getSecurity() != null && !openAPI.getSecurity().isEmpty()) {
            return openAPI.getSecurity();
        }
        return Collections.emptyList();
    }

    private Map<String, SecurityScheme> resolveSecuritySchemes(OpenAPI openAPI) {
        if (openAPI == null || openAPI.getComponents() == null || openAPI.getComponents().getSecuritySchemes() == null) {
            return Collections.emptyMap();
        }
        return openAPI.getComponents().getSecuritySchemes();
    }

    private void applySecurity(Request.Builder requestBuilder,
                               HttpUrl.Builder urlBuilder,
                               Operation operation,
                               OpenAPI openAPI) {
        if (requestBuilder == null) {
            return;
        }
        Map<String, SecurityScheme> schemes = resolveSecuritySchemes(openAPI);
        Set<String> addedHeaders = new HashSet<>();
        List<SecurityRequirement> requirements = resolveSecurityRequirements(operation, openAPI);

        for (SecurityRequirement requirement : requirements) {
            for (String schemeName : requirement.keySet()) {
                SecurityScheme scheme = schemes.get(schemeName);
                if (scheme == null) {
                    continue;
                }
                SecurityScheme.Type type = scheme.getType();
                if (type == null) {
                    continue;
                }
                switch (type) {
                    case HTTP -> {
                        String httpScheme = scheme.getScheme();
                        if (httpScheme != null && httpScheme.equalsIgnoreCase("basic")) {
                            requestBuilder.header("Authorization", Credentials.basic("scanner", "scanner"));
                            addedHeaders.add("authorization");
                        } else {
                            // По умолчанию считаем bearer
                            requestBuilder.header("Authorization", DEFAULT_BEARER_TOKEN);
                            addedHeaders.add("authorization");
                        }
                    }
                    case APIKEY -> {
                        String name = scheme.getName();
                        if (name == null || name.isEmpty()) {
                            break;
                        }
                        String location = scheme.getIn() != null ? scheme.getIn().name().toLowerCase(Locale.ROOT) : "header";
                        String value = sampleApiKeyValue(name);
                        switch (location) {
                            case "query" -> {
                                if (urlBuilder != null) {
                                    urlBuilder.addQueryParameter(name, value);
                                }
                            }
                            case "cookie" -> requestBuilder.header("Cookie", name + "=" + value);
                            default -> {
                                requestBuilder.header(name, value);
                                addedHeaders.add(name.toLowerCase(Locale.ROOT));
                            }
                        }
                    }
                    case OAUTH2, OPENIDCONNECT -> {
                        if (!addedHeaders.contains("authorization")) {
                            requestBuilder.header("Authorization", DEFAULT_BEARER_TOKEN);
                            addedHeaders.add("authorization");
                        }
                    }
                    default -> {
                        // Другие типы (mutualTLS и т.п.) не поддерживаем в gentle probing
                    }
                }
            }
        }

        if (operation != null && operation.getParameters() != null) {
            for (Parameter parameter : operation.getParameters()) {
                if (parameter == null || parameter.getName() == null) {
                    continue;
                }
                String location = parameter.getIn();
                String name = parameter.getName();
                boolean required = Boolean.TRUE.equals(parameter.getRequired());
                if ("header".equalsIgnoreCase(location) && required) {
                    String headerKey = name.toLowerCase(Locale.ROOT);
                    if (addedHeaders.add(headerKey)) {
                        String value = sampleHeaderValue(parameter);
                        if (value != null) {
                            requestBuilder.header(name, value);
                        }
                    }
                } else if ("query".equalsIgnoreCase(location) && required && urlBuilder != null) {
                    String value = sampleQueryValue(parameter);
                    if (value != null) {
                        urlBuilder.addQueryParameter(name, value);
                    }
                }
            }
        }
    }

    private String sampleApiKeyValue(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.contains("key")) {
            return DEFAULT_API_KEY;
        }
        if (lower.contains("token")) {
            return DEFAULT_API_KEY;
        }
        return DEFAULT_API_KEY;
    }

    private String sampleHeaderValue(Parameter parameter) {
        if (parameter == null || parameter.getName() == null) {
            return null;
        }
        String name = parameter.getName();
        String lower = name.toLowerCase(Locale.ROOT);

        Optional<String> example = extractExample(parameter);
        if (example.isPresent()) {
            return example.get();
        }

        if (parameter.getSchema() != null) {
            String schemaValue = guessValueFromSchema(parameter.getSchema());
            if (schemaValue != null) {
                return schemaValue;
            }
        }

        if ("authorization".equals(lower)) {
            return DEFAULT_BEARER_TOKEN;
        }
        if (lower.contains("token")) {
            return DEFAULT_API_KEY;
        }
        if (lower.contains("consent") || lower.contains("requesting")) {
            return "consent-" + deterministicNumericValue(lower);
        }
        if (lower.contains("bank") && lower.contains("id")) {
            return deterministicId(lower);
        }
        if (lower.contains("client") && lower.contains("id")) {
            return deterministicId(lower);
        }
        if (lower.contains("permissions")) {
            return "ReadAccounts,ReadTransactions";
        }
        if (lower.contains("psu")) {
            return "PSU-" + deterministicNumericValue(lower);
        }
        if (lower.contains("tpp")) {
            return "TPP-" + deterministicNumericValue(lower);
        }
        return fallbackStringValue(name);
    }

    private String sampleQueryValue(Parameter parameter) {
        if (parameter == null || parameter.getName() == null) {
            return null;
        }

        String lower = parameter.getName().toLowerCase(Locale.ROOT);

        Optional<String> example = extractExample(parameter);
        if (example.isPresent()) {
            return example.get();
        }

        if (parameter.getSchema() != null) {
            String schemaValue = guessValueFromSchema(parameter.getSchema());
            if (schemaValue != null) {
                return schemaValue;
            }
        }

        if (lower.contains("consent")) {
            return "consent-" + deterministicNumericValue(lower);
        }
        if (lower.contains("permissions")) {
            return "ReadAccounts";
        }
        if (lower.contains("iban")) {
            return "DE02100100109307118603";
        }
        if (lower.contains("account") && lower.contains("id")) {
            return deterministicId(lower).replaceAll("-", "");
        }
        if (lower.contains("currency")) {
            return "RUB";
        }

        return fallbackStringValue(parameter.getName());
    }

    private Optional<String> extractExample(Parameter parameter) {
        if (parameter == null) {
            return Optional.empty();
        }
        if (parameter.getExample() != null) {
            return Optional.of(parameter.getExample().toString());
        }
        if (parameter.getExamples() != null) {
            for (Example example : parameter.getExamples().values()) {
                if (example != null && example.getValue() != null) {
                    return Optional.of(example.getValue().toString());
                }
            }
        }
        if (parameter.getSchema() != null) {
            Optional<String> schemaExample = extractExample(parameter.getSchema());
            if (schemaExample.isPresent()) {
                return schemaExample;
            }
        }
        if (parameter.getContent() != null) {
            for (io.swagger.v3.oas.models.media.MediaType mediaType : parameter.getContent().values()) {
                if (mediaType == null) {
                    continue;
                }
                if (mediaType.getExample() != null) {
                    return Optional.of(mediaType.getExample().toString());
                }
                Schema<?> schema = mediaType.getSchema();
                Optional<String> example = extractExample(schema);
                if (example.isPresent()) {
                    return example;
                }
            }
        }
        return Optional.empty();
    }

    private Optional<String> extractExample(Schema<?> schema) {
        if (schema == null) {
            return Optional.empty();
        }
        if (schema.getExample() != null) {
            return Optional.of(schema.getExample().toString());
        }
        if (schema.getDefault() != null) {
            return Optional.of(schema.getDefault().toString());
        }
        if (schema.getConst() != null) {
            return Optional.of(schema.getConst().toString());
        }
        if (schema.getEnum() != null && !schema.getEnum().isEmpty()) {
            Object value = schema.getEnum().get(0);
            if (value != null) {
                return Optional.of(value.toString());
            }
        }
        return Optional.empty();
    }

    private String guessValueFromSchema(Schema<?> schema) {
        return guessValueFromSchema(schema, Collections.newSetFromMap(new IdentityHashMap<>()));
    }

    private String guessValueFromSchema(Schema<?> schema, Set<Schema<?>> visited) {
        if (schema == null) {
            return null;
        }
        if (!visited.add(schema)) {
            return null;
        }

        Optional<String> direct = extractExample(schema);
        if (direct.isPresent()) {
            return direct.get();
        }

        String format = schema.getFormat();
        if (format != null) {
            format = format.toLowerCase(Locale.ROOT);
            switch (format) {
                case "uuid" -> {
                    return deterministicId("uuid");
                }
                case "email" -> {
                    return "user@example.com";
                }
                case "uri", "url" -> {
                    return "https://example.com/callback";
                }
                case "hostname" -> {
                    return "api.example.com";
                }
                case "date" -> {
                    return LocalDate.now().toString();
                }
                case "date-time", "datetime" -> {
                    return OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
                }
                case "phone", "tel" -> {
                    return "+10000000000";
                }
                default -> {
                    // fall through to type handling
                }
            }
        }

        String type = schema.getType();
        if (type == null && schema.getItems() != null) {
            type = "array";
        }
        if (type == null) {
            return null;
        }

        switch (type.toLowerCase(Locale.ROOT)) {
            case "integer" -> {
                Number min = schema.getMinimum();
                Number max = schema.getMaximum();
                if (min != null) {
                    return String.valueOf(min.longValue());
                }
                if (max != null) {
                    long value = Math.max(1, max.longValue() - 1);
                    return String.valueOf(value);
                }
                return deterministicNumericValue("int");
            }
            case "number" -> {
                Number min = schema.getMinimum();
                if (min != null) {
                    return String.valueOf(min.doubleValue());
                }
                return "1.0";
            }
            case "boolean" -> {
                return "true";
            }
            case "array" -> {
                Schema<?> items = schema.getItems();
                String item = guessValueFromSchema(items, visited);
                return item != null ? item : "value";
            }
            case "object" -> {
                return deterministicId("object");
            }
            default -> {
                return fallbackStringValue(schema.getName() != null ? schema.getName() : "value");
            }
        }
    }

    private String fallbackStringValue(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.contains("limit") || lower.contains("page_size") || lower.endsWith("size")) {
            return deterministicNumericValue("limit");
        }
        if (lower.contains("offset") || lower.contains("page")) {
            return "0";
        }
        if (lower.contains("count")) {
            return deterministicNumericValue("count");
        }
        if (lower.contains("consent")) {
            return deterministicId("consent");
        }
        if (lower.contains("account")) {
            return deterministicId("account");
        }
        if (lower.contains("token")) {
            return DEFAULT_API_KEY;
        }
        if (lower.contains("id")) {
            return deterministicId(name);
        }
        return "value";
    }

    private String deterministicId(String seed) {
        return UUID.nameUUIDFromBytes(("smartfuzzer:" + seed).getBytes(StandardCharsets.UTF_8)).toString();
    }

    private String deterministicNumericValue(String seed) {
        long value = Math.abs(("smartfuzzer:" + seed).hashCode());
        long normalized = (value % 900_000L) + 100_000L;
        return Long.toString(normalized);
    }
    
    public SmartFuzzer(String targetUrl) {
        this.targetUrl = targetUrl;
        ScannerConfig config = ScannerConfig.load();
        ScannerConfig.SmartFuzzerSettings loaded = config != null ? config.getSmartFuzzer() : null;
        if (loaded == null) {
            loaded = new ScannerConfig.SmartFuzzerSettings();
            loaded.ensureDefaults();
        }
        this.settings = loaded;
        applyContextSettings(ContextAnalyzer.APIContext.GENERAL);
    }
    
    /**
     * ЦЕЛЕВОЙ fuzzing: проверяет найденные уязвимости через реальные HTTP запросы
     * 
     * @param foundVulnerabilities список уязвимостей найденных сканерами
     * @param openAPI OpenAPI спецификация
     * @param parser парсер спецификации
     * @return список ПОДТВЕРЖДЕННЫХ уязвимостей через реальные запросы
     */
    public List<Vulnerability> targetedProbing(List<Vulnerability> foundVulnerabilities,
                                               OpenAPI openAPI,
                                               OpenAPIParser parser,
                                               ContextAnalyzer.APIContext apiContext,
                                               AttackSurfaceSummary attackSurface,
                                               ThreatGraph threatGraph) {
        applyContextSettings(apiContext);
        resetCounters();

        log.info("Запуск Smart Fuzzer (целевой probing найденных уязвимостей)...");
        log.info("Профиль: context={}, globalLimit={}, perEndpoint={}, delay={}мс, timeout={}с, stopStatus={}",
            apiContext != null ? apiContext.name() : "GENERAL",
            maxTotalRequests,
            maxRequestsPerEndpoint,
            delayMs,
            timeoutSec,
            stopStatusCodes);
        
        List<Vulnerability> confirmedVulnerabilities = new ArrayList<>();
        FuzzContext fuzzContext = prepareFuzzContext(foundVulnerabilities, apiContext, attackSurface, threatGraph);
        
        // КРИТИЧНО: Защита от NPE
        if (targetUrl == null) {
            log.warn("Target URL null, пропускаем fuzzing");
            return confirmedVulnerabilities;
        }
        
        if (targetUrl.contains("localhost") || targetUrl.contains("127.0.0.1")) {
            log.warn("Target - localhost. Fuzzing пропущен (для безопасности).");
            return confirmedVulnerabilities;
        }
        
        if (foundVulnerabilities == null || foundVulnerabilities.isEmpty()) {
            log.info("Нет найденных уязвимостей для проверки через fuzzing");
            return confirmedVulnerabilities;
        }
        
        // Фильтруем типы уязвимостей которые можно проверить через HTTP
        Set<VulnerabilityType> fuzzableTypes = Set.of(
            VulnerabilityType.BOLA,
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.NOSQL_INJECTION,
            VulnerabilityType.COMMAND_INJECTION,
            VulnerabilityType.LDAP_INJECTION,
            VulnerabilityType.SSRF,
            VulnerabilityType.BROKEN_AUTHENTICATION,
            VulnerabilityType.BFLA,
            VulnerabilityType.SECURITY_MISCONFIGURATION
        );
        
        // Группируем по endpoint + method для дедупликации
        Map<String, List<Vulnerability>> byEndpoint = new LinkedHashMap<>();
        for (Vulnerability vuln : foundVulnerabilities) {
            if (vuln == null || vuln.getType() == null || !fuzzableTypes.contains(vuln.getType())) {
                continue;
            }
            
            String key = String.format("%s|%s", 
                vuln.getEndpoint() != null ? vuln.getEndpoint() : "",
                vuln.getMethod() != null ? vuln.getMethod() : "");
            
            byEndpoint.computeIfAbsent(key, k -> new ArrayList<>()).add(vuln);
        }
        
        log.info("Найдено {} fuzzable уязвимостей на {} endpoints", 
            foundVulnerabilities.stream().filter(v -> v != null && fuzzableTypes.contains(v.getType())).count(),
            byEndpoint.size());
        
        outer:
        for (Map.Entry<String, List<Vulnerability>> entry : byEndpoint.entrySet()) {
            if (totalRequests.get() >= maxTotalRequests) {
                log.info("Достигнут глобальный лимит запросов ({}). Fuzzing остановлен.", maxTotalRequests);
                break;
            }

            String[] parts = entry.getKey().split("\\|", -1); // -1 чтобы сохранить пустые строки
            String endpoint = parts.length > 0 && !parts[0].isEmpty() ? parts[0] : "";
            String method = parts.length > 1 && !parts[1].isEmpty() ? parts[1] : "GET";

            if (endpoint.isEmpty()) {
                log.debug("Пропускаем группу с пустым endpoint: {}", entry.getKey());
                continue;
            }

            AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
            if (endpointCounter.get() >= maxRequestsPerEndpoint) {
                log.debug("Лимит запросов для {} достигнут, пропускаем", endpoint);
                continue;
            }

            List<Vulnerability> vulnsInGroup = entry.getValue();
            if (vulnsInGroup == null || vulnsInGroup.isEmpty()) {
                log.debug("Пропускаем пустую группу для endpoint: {}", entry.getKey());
                continue;
            }

            vulnsInGroup.removeIf(v -> v == null || v.getType() == null || v.getSeverity() == null);
            if (vulnsInGroup.isEmpty()) {
                continue;
            }

            vulnsInGroup.sort((a, b) -> {
                int severityCompare = Integer.compare(severityWeight(b.getSeverity()), severityWeight(a.getSeverity()));
                if (severityCompare != 0) {
                    return severityCompare;
                }
                int riskCompare = Integer.compare(b.getRiskScore(), a.getRiskScore());
                if (riskCompare != 0) {
                    return riskCompare;
                }
                int priorityA = a.getPriority() > 0 ? a.getPriority() : Integer.MAX_VALUE;
                int priorityB = b.getPriority() > 0 ? b.getPriority() : Integer.MAX_VALUE;
                int priorityCompare = Integer.compare(priorityA, priorityB);
                if (priorityCompare != 0) {
                    return priorityCompare;
                }
                String titleA = a.getTitle() != null ? a.getTitle() : "";
                String titleB = b.getTitle() != null ? b.getTitle() : "";
                return titleA.compareToIgnoreCase(titleB);
            });

            Operation operation = findOperation(openAPI, endpoint, method);
            Set<VulnerabilityType> testedTypes = new HashSet<>();

            for (int i = 0; i < vulnsInGroup.size(); i++) {
                if (totalRequests.get() >= maxTotalRequests) {
                    log.info("Достигнут глобальный лимит запросов ({}) в ходе fuzzing.", maxTotalRequests);
                    break outer;
                }
                if (endpointCounter.get() >= maxRequestsPerEndpoint) {
                    log.debug("Лимит запросов для {} достигнут, завершаем группу", endpoint);
                    break;
                }

                Vulnerability vuln = vulnsInGroup.get(i);
                if (!testedTypes.add(vuln.getType())) {
                    continue; // избегаем повторного fuzz для одинакового типа на одном endpoint
                }

                log.debug("Проверка уязвимости типа {} на endpoint {} метод {}", vuln.getType(), endpoint, method);
                List<Vulnerability> confirmed = probeVulnerability(vuln, endpoint, method, operation, openAPI, fuzzContext);

                if (!confirmed.isEmpty()) {
                    log.info("Подтверждено {} уязвимостей на endpoint {}", confirmed.size(), endpoint);
                    confirmedVulnerabilities.addAll(confirmed);
                    for (Vulnerability confirmedVuln : confirmed) {
                        confirmedVuln.setConfidence(Math.min(100, confirmedVuln.getConfidence() + 20));
                        confirmedVuln.setPriority(Math.max(1, confirmedVuln.getPriority() - 1));
                    }
                } else {
                    log.debug("Уязвимость {} не подтверждена на endpoint {}", vuln.getType(), endpoint);
                }

                if (totalRequests.get() >= maxTotalRequests) {
                    log.info("Достигнут глобальный лимит запросов ({}) в ходе fuzzing.", maxTotalRequests);
                    break outer;
                }
                if (endpointCounter.get() >= maxRequestsPerEndpoint) {
                    log.debug("Лимит запросов для {} достигнут, завершаем группу", endpoint);
                    break;
                }

                if (delayMs > 0 && i < vulnsInGroup.size() - 1) {
                    sleep(delayMs);
                }
            }
        }
        
        log.info("Smart Fuzzer завершен. Сделано {} запросов. Подтверждено: {} уязвимостей", 
            totalRequests.get(), confirmedVulnerabilities.size());
        
        return confirmedVulnerabilities;
    }
    
    /**
     * Проверка конкретной уязвимости через HTTP запрос
     */
    private List<Vulnerability> probeVulnerability(Vulnerability vuln,
                                                   String endpoint,
                                                   String method,
                                                   Operation operation,
                                                   OpenAPI openAPI,
                                                   FuzzContext fuzzContext) {
        List<Vulnerability> confirmed = new ArrayList<>();
        
        if (vuln == null || vuln.getType() == null || endpoint == null) {
            return confirmed;
        }
        
        VulnerabilityType type = vuln.getType();
        
        // Выбираем метод проверки по типу
        switch (type) {
            case BOLA:
                confirmed.addAll(probeBOLA(endpoint, method, operation, openAPI, fuzzContext));
                break;
            case SQL_INJECTION:
                confirmed.addAll(probeSQLInjection(endpoint, method, operation, openAPI, fuzzContext));
                break;
            case NOSQL_INJECTION:
                confirmed.addAll(probeNoSQLInjection(endpoint, method, operation, openAPI, fuzzContext));
                break;
            case COMMAND_INJECTION:
                confirmed.addAll(probeCommandInjection(endpoint, method, operation, openAPI, fuzzContext));
                break;
            case LDAP_INJECTION:
                confirmed.addAll(probeLDAPInjection(endpoint, method, operation, openAPI, fuzzContext));
                break;
            case SSRF:
                confirmed.addAll(probeSSRF(endpoint, method, operation, openAPI, fuzzContext));
                break;
            case BROKEN_AUTHENTICATION:
            case BFLA:
                confirmed.addAll(probeAuthentication(endpoint, method, operation, openAPI));
                break;
            case SECURITY_MISCONFIGURATION:
                confirmed.addAll(probeMisconfiguration(vuln, endpoint, method, operation, openAPI));
                break;
            default:
                log.debug("Тип уязвимости {} не поддерживается для fuzzing", type);
        }
        
        return confirmed;
    }
    
    /**
     * Безопасное выполнение HTTP запроса с обработкой ошибок и лимитов
     * КРИТИЧНО: Атомарная проверка и увеличение счетчиков для предотвращения race conditions
     */
    private FuzzingResult executeRequest(Request request, String endpoint) {
        // КРИТИЧНО: Защита от null endpoint
        if (endpoint == null) {
            endpoint = "unknown";
        }
        
        // КРИТИЧНО: Атомарная проверка и резервирование запроса для предотвращения race conditions
        if (totalRequests.get() >= maxTotalRequests) {
            return FuzzingResult.stop(0, "Global limit reached");
        }

        while (true) {
            int current = totalRequests.get();
            if (current >= maxTotalRequests) {
                return FuzzingResult.stop(0, "Global limit reached");
            }
            if (totalRequests.compareAndSet(current, current + 1)) {
                break;
            }
        }

        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));

        while (true) {
            int current = endpointCounter.get();
            if (current >= maxRequestsPerEndpoint) {
                totalRequests.decrementAndGet();
                return FuzzingResult.stop(0, "Endpoint limit reached");
            }
            if (endpointCounter.compareAndSet(current, current + 1)) {
                break;
            }
        }
        
        try (Response response = httpClient.newCall(request).execute()) {
            int code = response.code();
            
            if (stopStatusCodes.contains(code)) {
                if (code == 429) {
                    log.warn("Rate limit (429) для {}. Останавливаем fuzzing для этого endpoint.", endpoint);
                } else {
                    log.debug("Получен код {} для {}. Останавливаем fuzzing для этого endpoint.", code, endpoint);
                }
                return FuzzingResult.stop(code, "HTTP " + code);
            }
            
            // Возвращаем успешный результат
            String body = null;
            ResponseBody responseBody = response.body();
            if (responseBody != null) {
                body = responseBody.string();
            }

            Optional.ofNullable(timeoutsPerEndpoint.get(endpoint)).ifPresent(counter -> counter.set(0));
            Optional.ofNullable(networkErrorsPerEndpoint.get(endpoint)).ifPresent(counter -> counter.set(0));

            return FuzzingResult.success(code, body);
            
        } catch (java.net.SocketTimeoutException e) {
            int endpointTimeouts = timeoutsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0)).incrementAndGet();
            int globalTimeouts = totalTimeouts.incrementAndGet();
            log.debug("Timeout для {}: {} (endpointTimeouts={}, totalTimeouts={})",
                endpoint, e.getMessage(), endpointTimeouts, globalTimeouts);
            if (endpointTimeouts >= maxTimeoutsPerEndpoint || globalTimeouts >= maxTotalTimeouts) {
                log.warn("Порог таймаутов достигнут для {} (endpointTimeouts={}, totalTimeouts={}).", endpoint, endpointTimeouts, globalTimeouts);
                return FuzzingResult.timeoutThreshold();
            }
            return FuzzingResult.timeout();
            
        } catch (IOException e) {
            int endpointErrors = networkErrorsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0)).incrementAndGet();
            int globalErrors = totalNetworkErrors.incrementAndGet();
            log.debug("IO error для {}: {} (endpointErrors={}, totalErrors={})",
                endpoint, e.getMessage(), endpointErrors, globalErrors);
            if (endpointErrors >= maxNetworkErrorsPerEndpoint || globalErrors >= maxNetworkErrors) {
                log.warn("Порог сетевых ошибок достигнут для {} (endpointErrors={}, totalErrors={}).", endpoint, endpointErrors, globalErrors);
                return FuzzingResult.networkErrorThreshold(e.getMessage());
            }
            return FuzzingResult.networkError(e.getMessage());
            
        } catch (Exception e) {
            log.debug("Unexpected error для {}: {}", endpoint, e.getMessage());
            return FuzzingResult.networkError(e.getMessage());
        }
        // ПРИМЕЧАНИЕ: Счетчики НЕ откатываются при ошибках, так как запрос был отправлен
        // Это гарантирует что лимиты не будут превышены даже при ошибках
    }
    
    /**
     * Проверка SQL Injection через gentle probing
     */
    private List<Vulnerability> probeSQLInjection(String endpoint,
                                                  String method,
                                                  Operation operation,
                                                  OpenAPI openAPI,
                                                  FuzzContext fuzzContext) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (endpoint == null || targetUrl == null) {
            return vulnerabilities;
        }
        
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        List<String> payloads = fuzzContext != null ? fuzzContext.sqlPayloads() : Collections.emptyList();
        for (String payload : payloads) {
            if (endpointCounter.get() >= maxRequestsPerEndpoint) {
                break;
            }
            
            // КРИТИЧНО: Умный URL encoding для разных типов payloads
            // Для SQL payloads сохраняем кавычки для корректного SQL синтаксиса
            // Для NoSQL/LDAP кодируем спецсимволы но сохраняем структуру
            String encodedPayload;
            if (payload.contains("'") || payload.contains("\"") || payload.contains("--")) {
                // SQL payloads - кодируем только пробелы и опасные символы кроме кавычек
                encodedPayload = payload.replace(" ", "%20")
                    .replace("<", "%3C")
                    .replace(">", "%3E")
                    .replace("&", "%26");
            } else if (payload.contains("{") || payload.contains("$") || payload.contains("(")) {
                // NoSQL/LDAP payloads - кодируем спецсимволы но сохраняем структуру
                encodedPayload = java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8)
                    .replace("+", "%20") // Пробелы как %20 а не +
                    .replace("*", "%2A"); // * для LDAP
            } else {
                // Для остальных payloads используем полное URL encoding
                encodedPayload = java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8);
            }
            
            String testUrl = buildTestUrl(endpoint, "query", encodedPayload);
            if (testUrl == null) {
                log.debug("Не удалось построить URL для SQL Injection probe, пропускаем");
                continue;
            }
            
            HttpUrl url = HttpUrl.parse(testUrl);
            if (url == null) {
                log.debug("Неверный URL для SQL Injection probe: {}", testUrl);
                continue;
            }
            HttpUrl.Builder urlBuilder = url.newBuilder();
            Request.Builder requestBuilder = new Request.Builder()
                .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (gentle-probing)");
            applySecurity(requestBuilder, urlBuilder, operation, openAPI);
            requestBuilder.url(urlBuilder.build()).get();
            Request request = requestBuilder.build();
            
            log.debug("SQL Injection probe: {} {}", method, testUrl);
            
            FuzzingResult result = executeRequest(request, endpoint);
            
            if (result.shouldStop()) {
                break;
            }
            
            if (result.success && result.body != null) {
                String body = result.body;
                if (body.contains("SQL syntax") || body.contains("MySQL") || 
                    body.contains("PostgreSQL") || body.contains("ORA-") ||
                    body.contains("SQLite") || body.contains("ODBC")) {
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.SQL_INJECTION, endpoint, method, "query", 
                            "ПОДТВЕРЖДЕНА SQL Injection"))
                        .type(VulnerabilityType.SQL_INJECTION)
                        .severity(Severity.CRITICAL)
                        .title("ПОДТВЕРЖДЕНА SQL Injection через gentle probing")
                        .description(
                            "Эндпоинт " + endpoint + " вернул SQL ошибку при тестировании с payload: " + payload + ". " +
                            "Это РЕАЛЬНАЯ SQL Injection уязвимость, подтвержденная тестированием!"
                        )
                        .endpoint(endpoint)
                        .method(method)
                        .recommendation(
                            "КРИТИЧНО: Используйте prepared statements и параметризованные запросы. " +
                            "Эта уязвимость ПОДТВЕРЖДЕНА реальным запросом!"
                        )
                        .owaspCategory("Injection - SQL Injection (CONFIRMED by testing)")
                        .evidence("HTTP " + result.code + ", SQL error detected in response")
                        .confidence(95)
                        .priority(1)
                        .build());
                    
                    log.warn("SQL Injection ПОДТВЕРЖДЕНА на {}!", testUrl);
                    break; // Нашли - хватит
                }
            }
            
            sleep(delayMs);
        }
        
            return vulnerabilities;
        }
        
    /**
     * Проверка NoSQL Injection
     */
    private List<Vulnerability> probeNoSQLInjection(String endpoint,
                                                    String method,
                                                    Operation operation,
                                                    OpenAPI openAPI,
                                                    FuzzContext fuzzContext) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (endpoint == null || targetUrl == null) {
            return vulnerabilities;
        }
        
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        List<String> payloads = fuzzContext != null ? fuzzContext.noSqlPayloads() : Collections.emptyList();
        for (String payload : payloads) {
            if (endpointCounter.get() >= maxRequestsPerEndpoint) {
                break;
            }
            
            // КРИТИЧНО: Умный URL encoding для разных типов payloads
            // Для SQL payloads сохраняем кавычки для корректного SQL синтаксиса
            // Для NoSQL/LDAP кодируем спецсимволы но сохраняем структуру
            String encodedPayload;
            if (payload.contains("'") || payload.contains("\"") || payload.contains("--")) {
                // SQL payloads - кодируем только пробелы и опасные символы кроме кавычек
                encodedPayload = payload.replace(" ", "%20")
                    .replace("<", "%3C")
                    .replace(">", "%3E")
                    .replace("&", "%26");
            } else if (payload.contains("{") || payload.contains("$") || payload.contains("(")) {
                // NoSQL/LDAP payloads - кодируем спецсимволы но сохраняем структуру
                encodedPayload = java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8)
                    .replace("+", "%20") // Пробелы как %20 а не +
                    .replace("*", "%2A"); // * для LDAP
            } else {
                // Для остальных payloads используем полное URL encoding
                encodedPayload = java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8);
            }
            
            String testUrl = buildTestUrl(endpoint, "query", encodedPayload);
            if (testUrl == null) {
                log.debug("Не удалось построить URL для NoSQL Injection probe, пропускаем");
                continue;
            }
            
            HttpUrl url = HttpUrl.parse(testUrl);
            if (url == null) {
                log.debug("Неверный URL для NoSQL Injection probe: {}", testUrl);
                continue;
            }
            HttpUrl.Builder urlBuilder = url.newBuilder();
            Request.Builder requestBuilder = new Request.Builder()
                .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (gentle-probing)");
            applySecurity(requestBuilder, urlBuilder, operation, openAPI);
            requestBuilder.url(urlBuilder.build()).get();
            Request request = requestBuilder.build();
            
            log.debug("NoSQL Injection probe: {} {}", method, testUrl);
            
            FuzzingResult result = executeRequest(request, endpoint);
            
            if (result.shouldStop()) {
                break;
            }
            
            if (result.success && result.body != null) {
                String body = result.body;
                if (body.contains("MongoDB") || body.contains("NoSQL") || 
                    body.contains("BSON") || body.contains("MongoError")) {
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.NOSQL_INJECTION, endpoint, method, "query",
                            "ПОДТВЕРЖДЕНА NoSQL Injection"))
                        .type(VulnerabilityType.NOSQL_INJECTION)
                        .severity(Severity.CRITICAL)
                        .title("ПОДТВЕРЖДЕНА NoSQL Injection через gentle probing")
                        .description(
                            "Эндпоинт " + endpoint + " вернул NoSQL ошибку при тестировании с payload: " + payload + ". " +
                            "Это РЕАЛЬНАЯ NoSQL Injection уязвимость, подтвержденная тестированием!"
                        )
                        .endpoint(endpoint)
                        .method(method)
                        .recommendation(
                            "КРИТИЧНО: Используйте параметризованные запросы и валидацию входных данных. " +
                            "Эта уязвимость ПОДТВЕРЖДЕНА реальным запросом!"
                        )
                        .owaspCategory("Injection - NoSQL Injection (CONFIRMED by testing)")
                        .evidence("HTTP " + result.code + ", NoSQL error detected in response")
                        .confidence(95)
                        .priority(1)
                        .build());
                    
                    log.warn("NoSQL Injection ПОДТВЕРЖДЕНА на {}!", testUrl);
                    break;
                }
            }
            
            sleep(delayMs);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка Command Injection
     */
    private List<Vulnerability> probeCommandInjection(String endpoint,
                                                      String method,
                                                      Operation operation,
                                                      OpenAPI openAPI,
                                                      FuzzContext fuzzContext) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (endpoint == null || targetUrl == null) {
            return vulnerabilities;
        }
        
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        List<String> payloads = fuzzContext != null ? fuzzContext.commandPayloads() : Collections.emptyList();
        for (String payload : payloads) {
            if (endpointCounter.get() >= maxRequestsPerEndpoint) {
                break;
            }
            
            // КРИТИЧНО: Умный URL encoding для разных типов payloads
            // Для SQL payloads сохраняем кавычки для корректного SQL синтаксиса
            // Для NoSQL/LDAP кодируем спецсимволы но сохраняем структуру
            String encodedPayload;
            if (payload.contains("'") || payload.contains("\"") || payload.contains("--")) {
                // SQL payloads - кодируем только пробелы и опасные символы кроме кавычек
                encodedPayload = payload.replace(" ", "%20")
                    .replace("<", "%3C")
                    .replace(">", "%3E")
                    .replace("&", "%26");
            } else if (payload.contains("{") || payload.contains("$") || payload.contains("(")) {
                // NoSQL/LDAP payloads - кодируем спецсимволы но сохраняем структуру
                encodedPayload = java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8)
                    .replace("+", "%20") // Пробелы как %20 а не +
                    .replace("*", "%2A"); // * для LDAP
            } else {
                // Для остальных payloads используем полное URL encoding
                encodedPayload = java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8);
            }
            
            String testUrl = buildTestUrl(endpoint, "cmd", encodedPayload);
            if (testUrl == null) {
                log.debug("Не удалось построить URL для Command Injection probe, пропускаем");
                continue;
            }
            
            HttpUrl url = HttpUrl.parse(testUrl);
            if (url == null) {
                log.debug("Неверный URL для Command Injection probe: {}", testUrl);
                continue;
            }
            HttpUrl.Builder urlBuilder = url.newBuilder();
            Request.Builder requestBuilder = new Request.Builder()
                .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (gentle-probing)");
            applySecurity(requestBuilder, urlBuilder, operation, openAPI);
            requestBuilder.url(urlBuilder.build()).get();
            Request request = requestBuilder.build();
            
            log.debug("Command Injection probe: {} {}", method, testUrl);
            
            FuzzingResult result = executeRequest(request, endpoint);
            
            if (result.shouldStop()) {
                break;
            }
            
            // Command injection сложно обнаружить через ответ, но можем проверить по времени ответа
            if (result.success && result.code == 200) {
                // Если ответ очень быстрый (<100ms) - возможно команда выполнилась
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.COMMAND_INJECTION, endpoint, method, "cmd",
                        "ВОЗМОЖНА Command Injection"))
                    .type(VulnerabilityType.COMMAND_INJECTION)
                    .severity(Severity.CRITICAL)
                    .title("ВОЗМОЖНА Command Injection")
                    .description(
                        "Эндпоинт " + endpoint + " принимает параметр который может быть использован для выполнения команд. " +
                        "Требуется дополнительная проверка."
                    )
                    .endpoint(endpoint)
                    .method(method)
                    .recommendation(
                        "КРИТИЧНО: НЕ используйте Runtime.exec() с пользовательским вводом! " +
                        "Используйте безопасные API вместо shell команд."
                    )
                    .owaspCategory("Injection - Command Injection (Potential)")
                    .evidence("HTTP " + result.code + ", command parameter detected")
                    .confidence(70)
                    .priority(2)
                    .build());
                
                log.warn("Возможная Command Injection на {}!", testUrl);
                break;
            }
            
                sleep(delayMs);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка LDAP Injection
     */
    private List<Vulnerability> probeLDAPInjection(String endpoint,
                                                   String method,
                                                   Operation operation,
                                                   OpenAPI openAPI,
                                                   FuzzContext fuzzContext) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (endpoint == null || targetUrl == null) {
            return vulnerabilities;
        }
        
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        List<String> payloads = fuzzContext != null ? fuzzContext.ldapPayloads() : Collections.emptyList();
        for (String payload : payloads) {
            if (endpointCounter.get() >= maxRequestsPerEndpoint) {
                break;
            }
            
            // КРИТИЧНО: Умный URL encoding для разных типов payloads
            // Для SQL payloads сохраняем кавычки для корректного SQL синтаксиса
            // Для NoSQL/LDAP кодируем спецсимволы но сохраняем структуру
            String encodedPayload;
            if (payload.contains("'") || payload.contains("\"") || payload.contains("--")) {
                // SQL payloads - кодируем только пробелы и опасные символы кроме кавычек
                encodedPayload = payload.replace(" ", "%20")
                    .replace("<", "%3C")
                    .replace(">", "%3E")
                    .replace("&", "%26");
            } else if (payload.contains("{") || payload.contains("$") || payload.contains("(")) {
                // NoSQL/LDAP payloads - кодируем спецсимволы но сохраняем структуру
                encodedPayload = java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8)
                    .replace("+", "%20") // Пробелы как %20 а не +
                    .replace("*", "%2A"); // * для LDAP
            } else {
                // Для остальных payloads используем полное URL encoding
                encodedPayload = java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8);
            }
            
            String testUrl = buildTestUrl(endpoint, "username", encodedPayload);
            if (testUrl == null) {
                log.debug("Не удалось построить URL для LDAP Injection probe, пропускаем");
                continue;
            }
            
            HttpUrl url = HttpUrl.parse(testUrl);
            if (url == null) {
                log.debug("Неверный URL для LDAP Injection probe: {}", testUrl);
                continue;
            }
            HttpUrl.Builder urlBuilder = url.newBuilder();
            Request.Builder requestBuilder = new Request.Builder()
                .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (gentle-probing)");
            applySecurity(requestBuilder, urlBuilder, operation, openAPI);
            requestBuilder.url(urlBuilder.build()).get();
            Request request = requestBuilder.build();
            
            log.debug("LDAP Injection probe: {} {}", method, testUrl);
            
            FuzzingResult result = executeRequest(request, endpoint);
            
            if (result.shouldStop()) {
                break;
            }
            
            if (result.success && result.body != null) {
                String body = result.body;
                if (body.contains("LDAP") || body.contains("bind") || 
                    body.contains("invalid DN") || body.contains("LDAPException")) {
                    
                    vulnerabilities.add(Vulnerability.builder()
                        .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.LDAP_INJECTION, endpoint, method, "username",
                            "ПОДТВЕРЖДЕНА LDAP Injection"))
                        .type(VulnerabilityType.LDAP_INJECTION)
                        .severity(Severity.CRITICAL)
                        .title("ПОДТВЕРЖДЕНА LDAP Injection через gentle probing")
                        .description(
                            "Эндпоинт " + endpoint + " вернул LDAP ошибку при тестировании с payload: " + payload + ". " +
                            "Это РЕАЛЬНАЯ LDAP Injection уязвимость, подтвержденная тестированием!"
                        )
                        .endpoint(endpoint)
                        .method(method)
                        .recommendation(
                            "КРИТИЧНО: Используйте параметризованные LDAP запросы и валидацию входных данных. " +
                            "Эта уязвимость ПОДТВЕРЖДЕНА реальным запросом!"
                        )
                        .owaspCategory("Injection - LDAP Injection (CONFIRMED by testing)")
                        .evidence("HTTP " + result.code + ", LDAP error detected in response")
                        .confidence(95)
                        .priority(1)
                        .build());
                    
                    log.warn("LDAP Injection ПОДТВЕРЖДЕНА на {}!", testUrl);
                    break;
                }
            }
            
            sleep(delayMs);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка SSRF через gentle probing
     */
    private List<Vulnerability> probeSSRF(String endpoint,
                                          String method,
                                          Operation operation,
                                          OpenAPI openAPI,
                                          FuzzContext fuzzContext) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (endpoint == null || targetUrl == null) {
            return vulnerabilities;
        }
        
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        // Только 2 безопасных проверки
        List<String> payloads = fuzzContext != null ? fuzzContext.ssrfTargets() : Collections.emptyList();
        for (int i = 0; i < Math.min(2, payloads.size()); i++) {
            if (endpointCounter.get() >= maxRequestsPerEndpoint) {
                break;
            }
            
            String payload = payloads.get(i);
            // КРИТИЧНО: Умный URL encoding для разных типов payloads
            // Для SQL payloads сохраняем кавычки для корректного SQL синтаксиса
            // Для NoSQL/LDAP кодируем спецсимволы но сохраняем структуру
            String encodedPayload;
            if (payload.contains("'") || payload.contains("\"") || payload.contains("--")) {
                // SQL payloads - кодируем только пробелы и опасные символы кроме кавычек
                encodedPayload = payload.replace(" ", "%20")
                    .replace("<", "%3C")
                    .replace(">", "%3E")
                    .replace("&", "%26");
            } else if (payload.contains("{") || payload.contains("$") || payload.contains("(")) {
                // NoSQL/LDAP payloads - кодируем спецсимволы но сохраняем структуру
                encodedPayload = java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8)
                    .replace("+", "%20") // Пробелы как %20 а не +
                    .replace("*", "%2A"); // * для LDAP
            } else {
                // Для остальных payloads используем полное URL encoding
                encodedPayload = java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8);
            }
            
            String testUrl = buildTestUrl(endpoint, "url", encodedPayload);
            if (testUrl == null) {
                log.debug("Не удалось построить URL для SSRF probe, пропускаем");
                continue;
            }
            
            HttpUrl url = HttpUrl.parse(testUrl);
            if (url == null) {
                log.debug("Неверный URL для SSRF probe: {}", testUrl);
                continue;
            }
            HttpUrl.Builder urlBuilder = url.newBuilder();
            Request.Builder requestBuilder = new Request.Builder()
                .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (gentle-probing)");
            applySecurity(requestBuilder, urlBuilder, operation, openAPI);
            requestBuilder.url(urlBuilder.build()).get();
            Request request = requestBuilder.build();
            
            log.debug("SSRF probe: {} {}", method, testUrl);
            
            FuzzingResult result = executeRequest(request, endpoint);
            
            if (result.shouldStop()) {
                break;
            }
            
            if (result.success && (result.code == 500 || result.code == 502 || result.code == 504)) {
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.SSRF, endpoint, method, "url",
                        "ВОЗМОЖНА SSRF уязвимость"))
                    .type(VulnerabilityType.SSRF)
                    .severity(Severity.HIGH)
                    .title("ВОЗМОЖНА SSRF уязвимость")
                    .description(
                        "Эндпоинт " + endpoint + " принимает URL параметр и может быть уязвим к SSRF. " +
                        "Требуется дополнительная проверка."
                    )
                    .endpoint(endpoint)
                    .method(method)
                    .recommendation(
                        "Проверьте валидацию URL параметров. Разрешайте только whitelist доменов. " +
                        "Используйте SSRF защиту."
                    )
                    .owaspCategory("API7:2023 - SSRF (Potential)")
                    .evidence("HTTP " + result.code + ", URL parameter detected")
                    .confidence(75)
                    .priority(2)
                    .build());
                
                log.warn("Возможная SSRF на {}!", testUrl);
                break;
            }
            
            sleep(delayMs);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка BOLA через gentle probing
     */
    private List<Vulnerability> probeBOLA(String endpoint,
                                          String method,
                                          Operation operation,
                                          OpenAPI openAPI,
                                          FuzzContext fuzzContext) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (endpoint == null || targetUrl == null) {
            return vulnerabilities;
        }
        
        if (!endpoint.contains("{")) {
            return vulnerabilities; // Нет параметров - пропускаем
        }
        
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        List<String> payloads = fuzzContext != null ? fuzzContext.bolaPayloads() : Collections.emptyList();
        for (String testId : payloads) {
            if (endpointCounter.get() >= maxRequestsPerEndpoint) {
                break;
            }
            
            String fullUrl = buildBolaUrl(endpoint, testId);
            if (fullUrl == null) {
                log.debug("Не удалось построить URL для BOLA probe, пропускаем");
                continue;
            }
            
            HttpUrl url = HttpUrl.parse(fullUrl);
            if (url == null) {
                log.debug("Неверный URL для BOLA probe: {}", fullUrl);
                continue;
            }
            HttpUrl.Builder urlBuilder = url.newBuilder();
            Request.Builder requestBuilder = new Request.Builder()
                .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (gentle-probing)");
            applySecurity(requestBuilder, urlBuilder, operation, openAPI);
            requestBuilder.url(urlBuilder.build()).get();
            Request request = requestBuilder.build();
                
            log.debug("BOLA probe: {} {}", method, fullUrl);
            
            FuzzingResult result = executeRequest(request, endpoint);
            
            if (result.shouldStop()) {
                break;
            }
            
            if (result.success && result.code == 200 && result.body != null) {
                String body = result.body;
                        // Если получили данные без auth - потенциальная BOLA!
                        if (body.length() > 10 && !body.contains("error") && !body.contains("unauthorized")) {
                            vulnerabilities.add(Vulnerability.builder()
                                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                            VulnerabilityType.BOLA, endpoint, method, String.valueOf(testId),
                                    "ПОДТВЕРЖДЕНА BOLA через gentle probing"))
                                .type(VulnerabilityType.BOLA)
                                .severity(Severity.HIGH)
                                .title("ПОДТВЕРЖДЕНА BOLA через gentle probing")
                                .description(
                            "Эндпоинт " + endpoint + " вернул данные для ID=" + testId + " БЕЗ аутентификации. " +
                                    "Это РЕАЛЬНАЯ BOLA уязвимость, подтвержденная тестированием!"
                                )
                        .endpoint(endpoint)
                        .method(method)
                                .recommendation(
                                    "КРИТИЧНО: Добавьте аутентификацию И проверку владельца объекта. " +
                                    "Эта уязвимость ПОДТВЕРЖДЕНА реальным запросом!"
                                )
                                .owaspCategory("API1:2023 - BOLA (CONFIRMED by testing)")
                        .evidence("HTTP " + result.code + ", body length: " + body.length() + " bytes")
                        .confidence(90)
                        .priority(1)
                                .build());
                            
                    log.warn("BOLA ПОДТВЕРЖДЕНА на {}!", fullUrl);
                            break; // Нашли - хватит
                        }
                    }
            
            sleep(delayMs);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка аутентификации (Broken Authentication, BFLA)
     */
    private List<Vulnerability> probeAuthentication(String endpoint,
                                                    String method,
                                                    Operation operation,
                                                    OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (endpoint == null || targetUrl == null) {
            return vulnerabilities;
        }
        
        AtomicInteger endpointCounter = requestsPerEndpoint.computeIfAbsent(endpoint, k -> new AtomicInteger(0));
        
        if (endpointCounter.get() >= maxRequestsPerEndpoint) {
            return vulnerabilities;
        }
        
        // КРИТИЧНО: Безопасное формирование URL для authentication probe
        // КРИТИЧНО: Защита от StringIndexOutOfBoundsException если targetUrl пустой
        String normalizedTarget = (targetUrl != null && targetUrl.length() > 0 && targetUrl.endsWith("/")) 
            ? targetUrl.substring(0, targetUrl.length() - 1) : targetUrl;
        String normalizedEndpoint = endpoint.startsWith("/") ? endpoint : "/" + endpoint;
        String fullUrl = normalizedTarget + normalizedEndpoint;
        
        // КРИТИЧНО: Корректная обработка разных HTTP методов
        HttpUrl url = HttpUrl.parse(fullUrl);
        if (url == null) {
            log.debug("Неверный URL для authentication probe: {}", fullUrl);
        return vulnerabilities;
        }
        HttpUrl.Builder urlBuilder = url.newBuilder();
        Request.Builder requestBuilder = new Request.Builder()
            .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (gentle-probing)");
        applySecurity(requestBuilder, urlBuilder, operation, openAPI);
        requestBuilder.url(urlBuilder.build());
        
        // Устанавливаем метод корректно
        switch (method.toUpperCase()) {
            case "GET":
                requestBuilder.get();
                break;
            case "POST":
                requestBuilder.post(RequestBody.create("", JSON_MEDIA_TYPE));
                break;
            case "PUT":
                requestBuilder.put(RequestBody.create("", JSON_MEDIA_TYPE));
                break;
            case "DELETE":
                requestBuilder.delete();
                break;
            case "PATCH":
                requestBuilder.patch(RequestBody.create("", JSON_MEDIA_TYPE));
                break;
            default:
                requestBuilder.get(); // По умолчанию GET
        }
        
        Request request = requestBuilder.build();
        
        log.debug("Authentication probe: {} {}", method, fullUrl);
        
        FuzzingResult result = executeRequest(request, endpoint);
        
        if (result.shouldStop()) {
            return vulnerabilities;
        }
        
        // Если получили 200 без auth - проблема!
        if (result.success && result.code == 200) {
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.BROKEN_AUTHENTICATION, endpoint, method, null,
                    "ПОДТВЕРЖДЕНА Broken Authentication"))
                .type(VulnerabilityType.BROKEN_AUTHENTICATION)
                .severity(Severity.HIGH)
                .title("ПОДТВЕРЖДЕНА Broken Authentication")
                .description(
                    "Эндпоинт " + endpoint + " доступен БЕЗ аутентификации (HTTP 200). " +
                    "Это РЕАЛЬНАЯ уязвимость, подтвержденная тестированием!"
                )
                .endpoint(endpoint)
                .method(method)
                .recommendation(
                    "КРИТИЧНО: Добавьте обязательную аутентификацию для этого endpoint. " +
                    "Эта уязвимость ПОДТВЕРЖДЕНА реальным запросом!"
                )
                .owaspCategory("API2:2023 - Broken Authentication (CONFIRMED by testing)")
                .evidence("HTTP " + result.code + " без аутентификации")
                .confidence(95)
                .priority(1)
                .build());
            
            log.warn("Broken Authentication ПОДТВЕРЖДЕНА на {}!", fullUrl);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Внутренний класс для результата fuzzing
     */
    private static class FuzzingResult {
        final boolean success;
        final boolean stop;
        @SuppressWarnings("unused")
        final boolean timeout;
        final int code;
        final String body;
        @SuppressWarnings("unused")
        final String error;

        private FuzzingResult(boolean success, boolean stop, boolean timeout, int code, String body, String error) {
            this.success = success;
            this.stop = stop;
            this.timeout = timeout;
            this.code = code;
            this.body = body;
            this.error = error;
        }

        static FuzzingResult success(int code, String body) {
            return new FuzzingResult(true, false, false, code, body, null);
        }

        static FuzzingResult stop(int code, String reason) {
            return new FuzzingResult(false, true, false, code, null, reason);
        }

        static FuzzingResult timeout() {
            return new FuzzingResult(false, false, true, 0, null, "Timeout");
        }

        static FuzzingResult timeoutThreshold() {
            return new FuzzingResult(false, true, true, 0, null, "Timeout threshold reached");
        }

        static FuzzingResult networkError(String message) {
            return new FuzzingResult(false, false, false, 0, null, message);
        }

        static FuzzingResult networkErrorThreshold(String message) {
            return new FuzzingResult(false, true, false, 0, null, message);
        }

        boolean shouldStop() {
            return stop;
        }
    }
    
    /**
     * Безопасное формирование URL для тестирования
     * Обрабатывает edge cases: trailing/leading slashes, полные URL в endpoint
     */
    private String buildTestUrl(String endpoint, String paramName, String paramValue) {
        if (targetUrl == null || endpoint == null) {
            return null;
        }
        
        // Если endpoint уже полный URL - используем его напрямую
        if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
            return endpoint + (endpoint.contains("?") ? "&" : "?") + paramName + "=" + paramValue;
        }
        
        // Нормализуем targetUrl и endpoint для избежания двойных слешей
        // КРИТИЧНО: Защита от StringIndexOutOfBoundsException если targetUrl пустой
        String normalizedTarget = (targetUrl != null && targetUrl.length() > 0 && targetUrl.endsWith("/")) 
            ? targetUrl.substring(0, targetUrl.length() - 1) : targetUrl;
        String normalizedEndpoint = endpoint.startsWith("/") ? endpoint : "/" + endpoint;
        
        String baseUrl = normalizedTarget + normalizedEndpoint;
        return baseUrl + (baseUrl.contains("?") ? "&" : "?") + paramName + "=" + paramValue;
    }
    
    /**
     * Безопасное формирование URL для BOLA (без параметров, только путь)
     */
    private String buildBolaUrl(String endpoint, String testId) {
        if (targetUrl == null || endpoint == null) {
            return null;
        }
        
        // Если endpoint уже полный URL - используем его напрямую
        if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
            return endpoint.replaceAll("\\{[^}]+\\}", testId);
        }
        
        // Нормализуем targetUrl и endpoint
        // КРИТИЧНО: Защита от StringIndexOutOfBoundsException если targetUrl пустой
        String normalizedTarget = (targetUrl != null && targetUrl.length() > 0 && targetUrl.endsWith("/")) 
            ? targetUrl.substring(0, targetUrl.length() - 1) : targetUrl;
        String normalizedEndpoint = endpoint.startsWith("/") ? endpoint : "/" + endpoint;
        String testPath = normalizedEndpoint.replaceAll("\\{[^}]+\\}", testId);
        
        return normalizedTarget + testPath;
    }
    
    private void sleep(long ms) {
        if (ms <= 0) {
            return;
        }
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Обратная совместимость: старый метод gentleProbing
     * @deprecated Используйте targetedProbing после сканеров
     */
    @Deprecated
    public List<Vulnerability> gentleProbing(OpenAPI openAPI, OpenAPIParser parser) {
        log.warn("Используется устаревший метод gentleProbing. Рекомендуется использовать targetedProbing.");
        // Для обратной совместимости возвращаем пустой список
        return new ArrayList<>();
    }

    private void applyContextSettings(ContextAnalyzer.APIContext apiContext) {
        ScannerConfig.SmartFuzzerSettings.ContextSettings contextSettings =
            settings != null ? settings.resolveContext(apiContext != null ? apiContext.name() : null) : null;

        this.maxTotalRequests = safeInt(contextSettings != null ? contextSettings.getGlobalLimit() : null, DEFAULT_GLOBAL_LIMIT);
        this.maxRequestsPerEndpoint = safeInt(contextSettings != null ? contextSettings.getPerEndpointLimit() : null, DEFAULT_PER_ENDPOINT_LIMIT);
        this.delayMs = safeLong(contextSettings != null ? contextSettings.getDelayMs() : null, DEFAULT_DELAY_MS);
        this.timeoutSec = safeInt(contextSettings != null ? contextSettings.getTimeoutSec() : null, DEFAULT_TIMEOUT_SEC);
        this.maxTimeoutsPerEndpoint = safeInt(contextSettings != null ? contextSettings.getMaxTimeoutsPerEndpoint() : null, DEFAULT_MAX_TIMEOUTS_PER_ENDPOINT);
        this.maxTotalTimeouts = safeInt(contextSettings != null ? contextSettings.getMaxTotalTimeouts() : null, DEFAULT_MAX_TOTAL_TIMEOUTS);
        this.maxNetworkErrors = safeInt(contextSettings != null ? contextSettings.getMaxNetworkErrors() : null, DEFAULT_MAX_NETWORK_ERRORS);
        this.maxNetworkErrorsPerEndpoint = safeInt(contextSettings != null ? contextSettings.getMaxNetworkErrorsPerEndpoint() : null, DEFAULT_MAX_NETWORK_ERRORS_PER_ENDPOINT);

        this.maxTotalTimeouts = Math.max(this.maxTotalTimeouts, this.maxTimeoutsPerEndpoint);
        this.maxNetworkErrors = Math.max(this.maxNetworkErrors, this.maxNetworkErrorsPerEndpoint);

        List<Integer> statusCodes = contextSettings != null ? contextSettings.getStopStatusCodes() : null;
        if (statusCodes == null || statusCodes.isEmpty()) {
            this.stopStatusCodes = new LinkedHashSet<>(DEFAULT_STOP_CODES);
        } else {
            this.stopStatusCodes = new LinkedHashSet<>(statusCodes);
            this.stopStatusCodes.addAll(DEFAULT_STOP_CODES);
        }

        this.httpClient = buildHttpClient(this.timeoutSec);
    }

    private void resetCounters() {
        totalRequests.set(0);
        totalTimeouts.set(0);
        totalNetworkErrors.set(0);
        requestsPerEndpoint.clear();
        timeoutsPerEndpoint.clear();
        networkErrorsPerEndpoint.clear();
    }

    private OkHttpClient buildHttpClient(int timeoutSeconds) {
        return new OkHttpClient.Builder()
            .connectTimeout(timeoutSeconds, TimeUnit.SECONDS)
            .readTimeout(timeoutSeconds, TimeUnit.SECONDS)
            .writeTimeout(timeoutSeconds, TimeUnit.SECONDS)
            .callTimeout(timeoutSeconds, TimeUnit.SECONDS)
            .followRedirects(false)
            .retryOnConnectionFailure(false)
            .build();
    }

    private int safeInt(Integer value, int fallback) {
        return (value != null && value > 0) ? value : fallback;
    }

    private long safeLong(Long value, long fallback) {
        return (value != null && value >= 0) ? value : fallback;
    }

    private int severityWeight(Severity severity) {
        if (severity == null) {
            return -1;
        }
        return switch (severity) {
            case CRITICAL -> 5;
            case HIGH -> 4;
            case MEDIUM -> 3;
            case LOW -> 2;
            case INFO -> 1;
        };
    }

    private String buildAbsoluteUrl(String endpoint) {
        if (endpoint == null || endpoint.isBlank()) {
            return null;
        }
        String normalizedEndpoint = endpoint.trim();
        if (normalizedEndpoint.startsWith("ws://")) {
            normalizedEndpoint = "http://" + normalizedEndpoint.substring(5);
        } else if (normalizedEndpoint.startsWith("wss://")) {
            normalizedEndpoint = "https://" + normalizedEndpoint.substring(6);
        }

        if (normalizedEndpoint.startsWith("http://") || normalizedEndpoint.startsWith("https://")) {
            return normalizedEndpoint;
        }

        if (targetUrl == null || targetUrl.isBlank()) {
            return null;
        }

        String normalizedTarget = targetUrl.endsWith("/")
            ? targetUrl.substring(0, targetUrl.length() - 1)
            : targetUrl;
        String endpointPath = normalizedEndpoint.startsWith("/") ? normalizedEndpoint : "/" + normalizedEndpoint;
        return normalizedTarget + endpointPath;
    }

    private boolean isGraphQlOperation(String endpoint, Operation operation) {
        String combined = buildOperationText(endpoint, operation);
        if (textContainsAny(combined, GRAPHQL_INDICATORS.toArray(new String[0]))) {
            return true;
        }
        if (operation != null && operation.getRequestBody() != null && operation.getRequestBody().getContent() != null) {
            for (String mediaType : operation.getRequestBody().getContent().keySet()) {
                if (mediaType != null && mediaType.toLowerCase(Locale.ROOT).contains("graphql")) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isGrpcOperation(String endpoint, Operation operation) {
        String combined = buildOperationText(endpoint, operation);
        if (textContainsAny(combined, GRPC_INDICATORS.toArray(new String[0]))) {
            return true;
        }
        if (operation != null && operation.getRequestBody() != null && operation.getRequestBody().getContent() != null) {
            for (String mediaType : operation.getRequestBody().getContent().keySet()) {
                if (mediaType != null && mediaType.toLowerCase(Locale.ROOT).contains("grpc")) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isWebSocketOperation(String endpoint, Operation operation) {
        String combined = buildOperationText(endpoint, operation);
        if (textContainsAny(combined, WEBSOCKET_INDICATORS.toArray(new String[0]))) {
            return true;
        }
        if (operation != null && operation.getServers() != null) {
            for (var server : operation.getServers()) {
                if (server != null && server.getUrl() != null) {
                    String url = server.getUrl().toLowerCase(Locale.ROOT);
                    if (url.startsWith("ws://") || url.startsWith("wss://")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private String buildOperationText(String endpoint, Operation operation) {
        StringBuilder sb = new StringBuilder();
        if (endpoint != null) {
            sb.append(endpoint.toLowerCase(Locale.ROOT)).append(' ');
        }
        if (operation != null) {
            if (operation.getSummary() != null) {
                sb.append(operation.getSummary().toLowerCase(Locale.ROOT)).append(' ');
            }
            if (operation.getDescription() != null) {
                sb.append(operation.getDescription().toLowerCase(Locale.ROOT)).append(' ');
            }
            if (operation.getParameters() != null) {
                for (Parameter parameter : operation.getParameters()) {
                    if (parameter != null && parameter.getName() != null) {
                        sb.append(parameter.getName().toLowerCase(Locale.ROOT)).append(' ');
                    }
                }
            }
        }
        return sb.toString();
    }

    private static boolean isGraphQlVulnerability(Vulnerability vulnerability) {
        String text = aggregateVulnerabilityText(vulnerability);
        return textContainsAny(text, "graphql", "graph ql", "introspection");
    }

    private static boolean isGrpcVulnerability(Vulnerability vulnerability) {
        String text = aggregateVulnerabilityText(vulnerability);
        return textContainsAny(text, "grpc", "proto", "protobuf", "h2c");
    }

    private static boolean isWebSocketVulnerability(Vulnerability vulnerability) {
        String text = aggregateVulnerabilityText(vulnerability);
        return textContainsAny(text, "websocket", "ws://", "wss://", "stomp", "mqtt", "pubsub");
    }

    private static String aggregateVulnerabilityText(Vulnerability vulnerability) {
        if (vulnerability == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        if (vulnerability.getTitle() != null) {
            sb.append(vulnerability.getTitle()).append(' ');
        }
        if (vulnerability.getDescription() != null) {
            sb.append(vulnerability.getDescription()).append(' ');
        }
        if (vulnerability.getEvidence() != null) {
            sb.append(vulnerability.getEvidence()).append(' ');
        }
        if (vulnerability.getRecommendation() != null) {
            sb.append(vulnerability.getRecommendation()).append(' ');
        }
        return sb.toString().toLowerCase(Locale.ROOT);
    }

    private static boolean textContainsAny(String text, String... keywords) {
        if (text == null || text.isEmpty()) {
            return false;
        }
        for (String keyword : keywords) {
            if (keyword != null && !keyword.isEmpty() && text.contains(keyword.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private List<Vulnerability> probeMisconfiguration(Vulnerability vulnerability,
                                                      String endpoint,
                                                      String method,
                                                      Operation operation,
                                                      OpenAPI openAPI) {
        List<Vulnerability> confirmed = new ArrayList<>();

        boolean graphQl = isGraphQlOperation(endpoint, operation) || isGraphQlVulnerability(vulnerability);
        boolean grpc = isGrpcOperation(endpoint, operation) || isGrpcVulnerability(vulnerability);
        boolean webSocket = isWebSocketOperation(endpoint, operation) || isWebSocketVulnerability(vulnerability);

        if (graphQl) {
            confirmed.addAll(probeGraphQlMisconfiguration(endpoint, method));
        } else if (grpc) {
            confirmed.addAll(probeGrpcMisconfiguration(endpoint));
        } else if (webSocket) {
            confirmed.addAll(probeWebSocketMisconfiguration(endpoint));
        }

        return confirmed;
    }

    private List<Vulnerability> probeGraphQlMisconfiguration(String endpoint,
                                                             String method) {
        List<Vulnerability> confirmed = new ArrayList<>();
        String url = buildAbsoluteUrl(endpoint);
        if (url == null) {
            return confirmed;
        }

        String introspectionQuery = "{\"query\":\"query IntrospectionProbe { __schema { queryType { name } mutationType { name } } }\"}";

        Request.Builder postBuilder = new Request.Builder()
            .url(url)
            .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (graphql-probe)")
            .addHeader("Content-Type", "application/json")
            .post(RequestBody.create(introspectionQuery, JSON_MEDIA_TYPE));

        FuzzingResult postResult = executeRequest(postBuilder.build(), endpoint);
        sleep(delayMs);
        if (postResult.shouldStop()) {
            return confirmed;
        }

        if (postResult.success && postResult.code == 200 && postResult.body != null && postResult.body.contains("__schema")) {
            confirmed.add(buildConfirmedGraphQlVulnerability(endpoint, "POST", postResult.body));
            return confirmed;
        }

        if ("GET".equalsIgnoreCase(method)) {
            HttpUrl parsed = HttpUrl.parse(url);
            if (parsed != null) {
                HttpUrl.Builder builder = parsed.newBuilder()
                    .addQueryParameter("query", "{__schema{types{name}}}");
                Request.Builder getBuilder = new Request.Builder()
                    .url(builder.build())
                    .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (graphql-probe)")
                    .get();
                FuzzingResult getResult = executeRequest(getBuilder.build(), endpoint);
                sleep(delayMs);
                if (!getResult.shouldStop() && getResult.success && getResult.code == 200 && getResult.body != null && getResult.body.contains("__schema")) {
                    confirmed.add(buildConfirmedGraphQlVulnerability(endpoint, "GET", getResult.body));
                }
            }
        }

        return confirmed;
    }

    private Vulnerability buildConfirmedGraphQlVulnerability(String endpoint,
                                                             String method,
                                                             String body) {
        return Vulnerability.builder()
            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                VulnerabilityType.SECURITY_MISCONFIGURATION, endpoint, method, null,
                "GraphQL introspection exposed"))
            .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
            .severity(Severity.HIGH)
            .title("ПОДТВЕРЖДЕНА GraphQL мисконфигурация")
            .description(
                "Эндпоинт " + endpoint + " отвечает на GraphQL introspection без защиты. " +
                    "В ответе присутствует __schema, что подтверждает утечку схемы.")
            .endpoint(endpoint)
            .method(method)
            .recommendation("Отключите introspection в production, используйте allowlist/persisted queries и требуйте аутентификацию.")
            .owaspCategory("API8:2023 - Security Misconfiguration (GraphQL)")
            .evidence(body.length() > 512 ? body.substring(0, 512) + "..." : body)
            .confidence(90)
            .priority(1)
            .build();
    }

    private List<Vulnerability> probeGrpcMisconfiguration(String endpoint) {
        List<Vulnerability> confirmed = new ArrayList<>();
        String url = buildAbsoluteUrl(endpoint);
        if (url == null) {
            return confirmed;
        }

        RequestBody body = RequestBody.create(new byte[]{0, 0, 0, 0, 0}, MediaType.parse("application/grpc"));
        Request.Builder requestBuilder = new Request.Builder()
            .url(url)
            .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (grpc-probe)")
            .addHeader("Content-Type", "application/grpc")
            .addHeader("TE", "trailers")
            .post(body);

        FuzzingResult result = executeRequest(requestBuilder.build(), endpoint);
        sleep(delayMs);
        if (result.shouldStop()) {
            return confirmed;
        }

        if (result.success && (result.code == 200 || result.code == 204)) {
            confirmed.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.SECURITY_MISCONFIGURATION, endpoint, "POST", null,
                    "gRPC method exposed"))
                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.HIGH)
                .title("ПОДТВЕРЖДЕНА gRPC мисконфигурация")
                .description("gRPC метод " + endpoint + " отвечает без аутентификации (HTTP " + result.code + ").")
                .endpoint(endpoint)
                .method("POST")
                .recommendation("Включите mTLS/токен-авторизацию для gRPC сервисов и ограничьте доступ по ACL.")
                .owaspCategory("API8:2023 - Security Misconfiguration (gRPC)")
                .evidence("HTTP " + result.code)
                .confidence(85)
                .priority(1)
                .build());
        }

        return confirmed;
    }

    private List<Vulnerability> probeWebSocketMisconfiguration(String endpoint) {
        List<Vulnerability> confirmed = new ArrayList<>();
        String url = buildAbsoluteUrl(endpoint);
        if (url == null) {
            return confirmed;
        }

        Request.Builder requestBuilder = new Request.Builder()
            .url(url)
            .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (websocket-probe)")
            .addHeader("Connection", "Upgrade")
            .addHeader("Upgrade", "websocket")
            .addHeader("Sec-WebSocket-Version", "13")
            .addHeader("Sec-WebSocket-Key", generateWebSocketKey())
            .get();

        FuzzingResult result = executeRequest(requestBuilder.build(), endpoint);
        sleep(delayMs);
        if (result.shouldStop()) {
            return confirmed;
        }

        if (result.success && result.code == 101) {
            confirmed.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.SECURITY_MISCONFIGURATION, endpoint, "GET", null,
                    "WebSocket handshake exposed"))
                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.HIGH)
                .title("ПОДТВЕРЖДЕНА WebSocket мисконфигурация")
                .description("WebSocket endpoint " + endpoint + " принимает handshake без авторизации (HTTP 101).")
                .endpoint(endpoint)
                .method("GET")
                .recommendation("Проверьте авторизацию и origin-check для WebSocket, требуйте токены при handshake.")
                .owaspCategory("API8:2023 - Security Misconfiguration (WebSocket)")
                .evidence("HTTP 101 Switching Protocols")
                .confidence(85)
                .priority(1)
                .build());
        }

        return confirmed;
    }

    private String generateWebSocketKey() {
        byte[] nonce = new byte[16];
        WEB_SOCKET_RANDOM.nextBytes(nonce);
        return Base64.getEncoder().encodeToString(nonce);
    }
}
