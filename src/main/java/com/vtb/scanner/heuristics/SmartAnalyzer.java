package com.vtb.scanner.heuristics;

import com.vtb.scanner.analysis.SchemaConstraintAnalyzer;
import com.vtb.scanner.analysis.SchemaConstraintAnalyzer.SchemaConstraints;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.semantic.ContextAnalyzer;
import com.vtb.scanner.semantic.OperationClassifier;
import com.vtb.scanner.semantic.OperationClassifier.OperationType;
import com.vtb.scanner.util.AccessControlHeuristics;
import com.vtb.scanner.config.ScannerConfig;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * Умный анализатор структуры API
 * Вычисляет risk scores, health score, находит аномалии
 */
@Slf4j
public class SmartAnalyzer {
    
    /**
     * Анализ структуры API
     * @return Map с ключами: apiHealthScore, totalEndpoints, withAuth, withoutAuth
     */
    public static Map<String, Object> analyzeAPIStructure(OpenAPI openAPI) {
        Map<String, Object> result = new HashMap<>();
        
        if (openAPI == null || openAPI.getPaths() == null) {
            result.put("apiHealthScore", 0);
            result.put("totalEndpoints", 0);
            result.put("withAuth", 0);
            result.put("withoutAuth", 0);
            return result;
        }
        
        int totalEndpoints = 0;
        int withAuth = 0;
        int withoutAuth = 0;
        
        for (PathItem pathItem : openAPI.getPaths().values()) {
            List<Operation> operations = getAllOperations(pathItem);
            totalEndpoints += operations.size();
            
            for (Operation op : operations) {
                if (hasSecurity(op, openAPI)) {
                    withAuth++;
                } else {
                    withoutAuth++;
                }
            }
        }
        
        // Health Score: процент эндпоинтов с auth
        long healthScore = totalEndpoints > 0 ? 
            (withAuth * 100L / totalEndpoints) : 0;
        
        result.put("apiHealthScore", healthScore);
        result.put("totalEndpoints", totalEndpoints);
        result.put("withAuth", withAuth);
        result.put("withoutAuth", withoutAuth);
        
        return result;
    }
    
    /**
     * Найти аномалии в структуре API
     */
    public static List<String> findAnomalies(OpenAPI openAPI) {
        List<String> anomalies = new ArrayList<>();
        
        if (openAPI == null || openAPI.getPaths() == null) {
            return anomalies;
        }
        
        Map<String, Object> structure = analyzeAPIStructure(openAPI);
        long healthScore = ((Number) structure.get("apiHealthScore")).longValue();
        int totalEndpoints = (Integer) structure.get("totalEndpoints");
        int withoutAuth = (Integer) structure.get("withoutAuth");
        
        // Низкий health score
        if (healthScore < 50 && totalEndpoints > 0) {
            anomalies.add(String.format(
                "Низкий уровень безопасности: только %d%% эндпоинтов защищены аутентификацией",
                healthScore
            ));
        }
        
        // Много эндпоинтов без auth
        if (withoutAuth > totalEndpoints * 0.5 && totalEndpoints > 5) {
            anomalies.add(String.format(
                "Большое количество незащищенных эндпоинтов: %d из %d",
                withoutAuth, totalEndpoints
            ));
        }
        
        // Проверка на debug endpoints
        for (String path : openAPI.getPaths().keySet()) {
            String lowerPath = path.toLowerCase();
            if (lowerPath.contains("debug") || lowerPath.contains("test") || 
                lowerPath.contains("dev") || lowerPath.contains("admin")) {
                PathItem pathItem = openAPI.getPaths().get(path);
                if (hasAnyOperation(pathItem)) {
                    Operation op = getFirstOperation(pathItem);
                    if (!hasSecurity(op, openAPI)) {
                        anomalies.add(String.format(
                            "Debug/admin эндпоинт без защиты: %s", path
                        ));
                    }
                }
            }
        }
        
        return anomalies;
    }
    
    /**
     * Вычислить risk score для операции
     * @return score 0-250
     */
    public static int calculateRiskScore(String path, String method, Operation operation, OpenAPI openAPI) {
        if (path == null || method == null || operation == null) {
            return 0;
        }

        int score = 0;
        SchemaConstraintAnalyzer constraintAnalyzer = openAPI != null
            ? new SchemaConstraintAnalyzer(openAPI)
            : null;
        String pathLower = path.toLowerCase(Locale.ROOT);
        String methodUpper = method.toUpperCase(Locale.ROOT);
        String combined = buildCombinedText(path, operation);
        OperationType opType = OperationClassifier.classify(path, method, operation);
        ContextAnalyzer.APIContext apiContext = ContextAnalyzer.detectContext(openAPI);
        boolean highContext = apiContext == ContextAnalyzer.APIContext.BANKING ||
            apiContext == ContextAnalyzer.APIContext.GOVERNMENT ||
            apiContext == ContextAnalyzer.APIContext.HEALTHCARE;
        ScannerConfig.RiskWeights weights = ScannerConfig.load().getRiskWeights();

        if ("DELETE".equals(methodUpper)) {
            score += 40;
        }

        if ("PUT".equals(methodUpper) || "PATCH".equals(methodUpper)) {
            score += 30;
        }

        if (pathLower.contains("admin") || pathLower.contains("delete") ||
            pathLower.contains("remove") || pathLower.contains("destroy")) {
            score += 50;
        }

        if (path.contains("{id}") || path.contains("{ID}") ||
            EnhancedRules.isIDParameter(path)) {
            score += 30;
        }

        if (!hasSecurity(operation, openAPI)) {
            score += 60;
        }

        if (pathLower.contains("payment") || pathLower.contains("transfer") ||
            pathLower.contains("withdraw") || pathLower.contains("deposit")) {
            score += 50;
        }

        if (MARKETPLACE_KEYWORDS.stream().anyMatch(combined::contains)) {
            int marketplaceWeight = highContext
                ? weight(weights != null ? weights.getMarketplaceFlowHighContext() : null, 60)
                : weight(weights != null ? weights.getMarketplaceFlow() : null, 40);
            score += marketplaceWeight;
        }

        if (GOVERNMENT_KEYWORDS.stream().anyMatch(combined::contains)) {
            score += weight(weights != null ? weights.getGovernmentFlow() : null, 50);
        }

        boolean highValueOperation = HIGH_VALUE_OPERATION_KEYWORDS.stream().anyMatch(combined::contains);
        if (highValueOperation) {
            score += highContext ? 80 : 60;
        }

        boolean bulkOperation = BULK_OPERATION_KEYWORDS.stream().anyMatch(combined::contains);
        if (bulkOperation) {
            score += highContext ? 70 : 50;
        }

        boolean loanOperation = LOAN_OPERATION_KEYWORDS.stream().anyMatch(combined::contains);
        if (loanOperation) {
            score += highContext ? 65 : 45;
        }

        if (opType == OperationType.LOGIN || opType == OperationType.REGISTER) {
            score += weight(weights != null ? weights.getLoginAbuse() : null, 30);
        }

        if (opType == OperationType.TRANSFER_MONEY || opType == OperationType.PAYMENT || opType == OperationType.WITHDRAWAL) {
            int financialWeight = highContext
                ? weight(weights != null ? weights.getMarketplaceFlowHighContext() : null, 60)
                : weight(weights != null ? weights.getMarketplaceFlow() : null, 40);
            score += financialWeight;
        }

        if (SESSION_KEYWORDS.stream().anyMatch(combined::contains)) {
            score += weight(weights != null ? weights.getSessionFlow() : null, 35);
        }

        boolean mentionsConsent = CONSENT_KEYWORDS.stream().anyMatch(combined::contains) || AccessControlHeuristics.mentionsPersonalData(operation);
        if (mentionsConsent) {
            boolean hasConsent = AccessControlHeuristics.hasConsentEvidence(operation, openAPI);
            if (hasConsent) {
                score += weight(weights != null ? weights.getConsentPresent() : null, 15);
            } else {
                int consentWeight = highContext
                    ? weight(weights != null ? weights.getConsentMissingHighContext() : null, 70)
                    : weight(weights != null ? weights.getConsentMissing() : null, 45);
                score += consentWeight;
            }
        }

        if (pathLower.contains("user") || pathLower.contains("account") ||
            pathLower.contains("profile")) {
            score += 20;
        }

        if (operation.getParameters() != null) {
            for (var param : operation.getParameters()) {
                SchemaConstraints constraints = constraintAnalyzer != null
                    ? constraintAnalyzer.analyzeParameter(param)
                    : null;
                if (EnhancedRules.isSQLInjectionRisk(param, constraints)) {
                    score += 40;
                }
            }
        }

        boolean hasTwoFactorMention = TWO_FACTOR_KEYWORDS.stream().anyMatch(combined::contains);
        if (hasTwoFactorMention) {
            score = Math.max(0, score - 15);
        }

        if (combined.contains("captcha") || combined.contains("rate limit") || combined.contains("throttle") ||
            combined.contains("anti-fraud")) {
            score = Math.max(0, score - 10);
        }

        if (RATE_LIMIT_KEYWORDS.stream().anyMatch(combined::contains)) {
            score = Math.max(0, score - 5);
        }

        if (DEVICE_PROTECTION_KEYWORDS.stream().anyMatch(combined::contains)) {
            score = Math.max(0, score - 10);
        }

        if (BEHAVIOR_ANALYTICS_KEYWORDS.stream().anyMatch(combined::contains)) {
            score = Math.max(0, score - 10);
        }

        boolean passwordResetFlow = PASSWORD_RESET_KEYWORDS.stream().anyMatch(combined::contains);
        if (passwordResetFlow) {
            if (!hasTwoFactorMention) {
                score += 35;
            }
            if (!RATE_LIMIT_KEYWORDS.stream().anyMatch(combined::contains)) {
                score += 15;
            }
        }

        boolean graphQlOperation = isGraphQlOperation(path, operation);
        if (graphQlOperation) {
            score += highContext ? 70 : 55;
            if (combined.contains("mutation") || combined.contains("subscription") || combined.contains("resolver")) {
                score += 15;
            }
            if (!hasSecurity(operation, openAPI)) {
                score += 25;
            }
        }

        boolean grpcOperation = isGrpcOperation(path, operation);
        if (grpcOperation) {
            score += highContext ? 60 : 45;
            if (!hasSecurity(operation, openAPI)) {
                score += 25;
            }
            if (combined.contains("stream") || combined.contains("bidirectional")) {
                score += 10;
            }
        }

        boolean webSocketOperation = isWebSocketOperation(path, operation);
        if (webSocketOperation) {
            score += 40;
            if (!hasSecurity(operation, openAPI)) {
                score += 20;
            }
            if (combined.contains("broadcast") || combined.contains("subscription") || combined.contains("channel")) {
                score += 10;
            }
        }

        score = (int) Math.round(score * contextMultiplier(weights, apiContext));

        return Math.min(250, Math.max(0, score));
    }
    
    /**
     * Преобразовать risk score в Severity
     */
    public static Severity severityFromRiskScore(int riskScore) {
        if (riskScore >= 150) {
            return Severity.CRITICAL;
        } else if (riskScore >= 100) {
            return Severity.HIGH;
        } else if (riskScore >= 50) {
            return Severity.MEDIUM;
        } else if (riskScore >= 20) {
            return Severity.LOW;
        } else {
            return Severity.INFO;
        }
    }
    
    // ═══════════════════════════════════════════════════════════════
    // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
    // ═══════════════════════════════════════════════════════════════
    
    private static final Set<String> MARKETPLACE_KEYWORDS = keywords(
        "checkout", "order", "cart", "basket", "purchase", "inventory", "shipment", "fulfillment", "refund", "return", "payout", "settlement", "merchant", "seller",
        "маркетплейс", "заказ", "корзина", "покупка", "возврат", "выплата", "поставщик", "товар",
        "marketplace", "sku", "витрина", "продажа", "маркет", "продавец"
    );
    private static final Set<String> GOVERNMENT_KEYWORDS = keywords(
        "permit", "license", "passport", "tax", "registry", "social", "benefit", "court", "fine", "ticket", "application",
        "gosuslugi", "esia", "smev", "pgu", "nalog", "rosreestr", "gibdd", "fns",
        "мфц", "услуга", "соцподдержка", "льгота", "выписка", "свидетельство", "реестр",
        "frgu"
    );
    private static final Set<String> SESSION_KEYWORDS = keywords(
        "session", "token", "jwt", "logout", "refresh", "revoke", "rotate",
        "сессия", "обновить токен", "выход", "sessionid", "auth-token", "access-token",
        "msisdn"
    );
    private static final Set<String> CONSENT_KEYWORDS = keywords(
        "consent", "permission", "scope", "allowed", "privacy", "sharing", "x-consent-id",
        "согласие", "esia", "esid", "оферта", "подтверждение", "согласование", "tpp", "qualified signature",
        "msisdn", "trusted device"
    );
    private static final Set<String> HIGH_VALUE_OPERATION_KEYWORDS = keywords(
        "treasury", "bulk payment", "mass payment", "swift", "rtgs", "wholesale payment",
        "payroll", "salary payout", "cash concentration", "treasury transfer", "intraday limit",
        "sbbol", "корпоративный платеж", "зарплатный проект", "казначейство", "fps", "sbp",
        "межбанковский перевод", "высокая сумма", "swift mt", "sbp transfer"
    );
    private static final Set<String> BULK_OPERATION_KEYWORDS = keywords(
        "batch", "bulk", "mass", "file upload payment", "payroll file", "multi transfer", "aggregate transfer",
        "массовый", "реестр", "ведомость", "пакет", "групповой платеж",
        "multitransfer", "зарплатная ведомость"
    );
    private static final Set<String> LOAN_OPERATION_KEYWORDS = keywords(
        "loan", "credit", "mortgage", "microloan", "installment", "disbursement", "issuance", "lending", "credit line",
        "кредит", "ипотека", "рассрочка", "займ", "овердрафт", "перекредитование",
        "leasing", "лизинг", "refinance", "страховая премия"
    );
    private static final Set<String> TWO_FACTOR_KEYWORDS = keywords(
        "2fa", "mfa", "otp", "two-factor", "two factor", "one-time password", "authenticator", "challenge code", "hardware token", "sms code",
        "смс код", "push-уведомление", "esia", "esid", "код подтверждения", "одноразовый пароль",
        "3ds", "miraccept", "visa secure", "mastercard identity check", "push code", "securecode",
        "voice biometric", "ussd"
    );
    private static final Set<String> RATE_LIMIT_KEYWORDS = keywords(
        "rate limit", "ratelimit", "throttle", "quota", "burst", "retry-after", "velocity",
        "лимит запросов", "ограничение частоты", "антиддоc", "скорость запросов",
        "ограничение нагрузки", "лимит частоты", "анти-дос", "анти-ддоc"
    );
    private static final Set<String> DEVICE_PROTECTION_KEYWORDS = keywords(
        "device fingerprint", "device binding", "trusted device", "device id", "behavioural biometric", "biometric",
        "фингерпринт устройства", "доверенное устройство", "привязка устройства", "биометрия",
        "psu-device", "device token", "fingerprint",
        "msisdn", "trusted sim", "device serial", "vin", "telematics unit"
    );
    private static final Set<String> BEHAVIOR_ANALYTICS_KEYWORDS = keywords(
        "behavior analytics", "behaviour analytics", "risk score", "fraud score", "velocity check",
        "anomaly detection", "fraud monitoring", "risk engine",
        "поведенческий анализ", "антифрод", "скоринг риска", "мониторинг транзакций",
        "risk-профиль", "поведенческая биометрия", "fraud engine",
        "telematics analytics", "device diagnostics"
    );
    private static final Set<String> PASSWORD_RESET_KEYWORDS = keywords(
        "password reset", "password recovery", "forgot password", "reset-token", "restore password",
        "восстановление пароля", "сброс пароля", "забыли пароль", "смена пароля",
        "reset password", "change password"
    );
    private static final Set<String> GRAPHQL_KEYWORDS = keywords(
        "graphql", "gql", "__schema", "apollo", "resolver", "mutation", "query", "subscription",
        "graph ql"
    );
    private static final Set<String> GRPC_KEYWORDS = keywords(
        "grpc", "rpc", "protobuf", "proto3", "h2c", "grpc-web", "channel", "stub"
    );
    private static final Set<String> WEBSOCKET_KEYWORDS = keywords(
        "websocket", "ws://", "wss://", "socket", "stomp", "mqtt", "pubsub", "subscribe", "broadcast"
    );

    private static List<Operation> getAllOperations(PathItem pathItem) {
        List<Operation> operations = new ArrayList<>();
        if (pathItem.getGet() != null) operations.add(pathItem.getGet());
        if (pathItem.getPost() != null) operations.add(pathItem.getPost());
        if (pathItem.getPut() != null) operations.add(pathItem.getPut());
        if (pathItem.getDelete() != null) operations.add(pathItem.getDelete());
        if (pathItem.getPatch() != null) operations.add(pathItem.getPatch());
        if (pathItem.getOptions() != null) operations.add(pathItem.getOptions());
        if (pathItem.getHead() != null) operations.add(pathItem.getHead());
        return operations;
    }
    
    private static boolean hasSecurity(Operation operation, OpenAPI openAPI) {
        if (operation == null) return false;
        
        // Проверка локальной security
        if (operation.getSecurity() != null && !operation.getSecurity().isEmpty()) {
            return true;
        }
        
        // Проверка глобальной security
        if (openAPI != null && openAPI.getSecurity() != null && 
            !openAPI.getSecurity().isEmpty()) {
            return true;
        }
        
        return false;
    }
    
    private static boolean hasAnyOperation(PathItem pathItem) {
        return pathItem.getGet() != null || pathItem.getPost() != null || 
               pathItem.getPut() != null || pathItem.getDelete() != null ||
               pathItem.getPatch() != null;
    }
    
    private static Operation getFirstOperation(PathItem pathItem) {
        if (pathItem.getGet() != null) return pathItem.getGet();
        if (pathItem.getPost() != null) return pathItem.getPost();
        if (pathItem.getPut() != null) return pathItem.getPut();
        if (pathItem.getDelete() != null) return pathItem.getDelete();
        if (pathItem.getPatch() != null) return pathItem.getPatch();
        return null;
    }

    private static String buildCombinedText(String path, Operation operation) {
        StringBuilder sb = new StringBuilder();
        if (path != null) {
            sb.append(path.toLowerCase(Locale.ROOT)).append(' ');
        }
        if (operation != null) {
            if (operation.getSummary() != null) {
                sb.append(operation.getSummary().toLowerCase(Locale.ROOT)).append(' ');
            }
            if (operation.getDescription() != null) {
                sb.append(operation.getDescription().toLowerCase(Locale.ROOT)).append(' ');
            }
        }
        return sb.toString();
    }

    private static boolean isGraphQlOperation(String path, Operation operation) {
        String pathLower = path != null ? path.toLowerCase(Locale.ROOT) : "";
        if (pathLower.contains("graphql")) {
            return true;
        }
        String combined = buildCombinedText(path, operation);
        if (GRAPHQL_KEYWORDS.stream().anyMatch(combined::contains)) {
            return true;
        }
        if (operation != null && operation.getRequestBody() != null && operation.getRequestBody().getContent() != null) {
            for (String mediaType : operation.getRequestBody().getContent().keySet()) {
                String lowered = mediaType.toLowerCase(Locale.ROOT);
                if (lowered.contains("graphql")) {
                    return true;
                }
            }
        }
        if (operation != null && operation.getParameters() != null) {
            for (Parameter parameter : operation.getParameters()) {
                if (parameter != null && parameter.getName() != null) {
                    String name = parameter.getName().toLowerCase(Locale.ROOT);
                    if ("query".equals(name) || "mutation".equals(name) || name.contains("graphql")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static boolean isGrpcOperation(String path, Operation operation) {
        String pathLower = path != null ? path.toLowerCase(Locale.ROOT) : "";
        if (pathLower.contains("grpc") || pathLower.contains(".proto") || pathLower.contains(".service")) {
            return true;
        }
        String combined = buildCombinedText(path, operation);
        if (GRPC_KEYWORDS.stream().anyMatch(combined::contains)) {
            return true;
        }
        if (operation != null && operation.getRequestBody() != null && operation.getRequestBody().getContent() != null) {
            for (String mediaType : operation.getRequestBody().getContent().keySet()) {
                String lowered = mediaType.toLowerCase(Locale.ROOT);
                if (lowered.contains("grpc") || lowered.contains("protobuf")) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isWebSocketOperation(String path, Operation operation) {
        String pathLower = path != null ? path.toLowerCase(Locale.ROOT) : "";
        if (pathLower.startsWith("ws") || pathLower.contains("websocket")) {
            return true;
        }
        String combined = buildCombinedText(path, operation);
        if (WEBSOCKET_KEYWORDS.stream().anyMatch(combined::contains)) {
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

    private static Set<String> keywords(String... values) {
        LinkedHashSet<String> set = new LinkedHashSet<>();
        for (String value : values) {
            if (value != null) {
                set.add(value);
            }
        }
        return Collections.unmodifiableSet(set);
    }

    private static int weight(Integer weight, int defaultValue) {
        return weight != null ? weight : defaultValue;
    }

    private static double contextMultiplier(ScannerConfig.RiskWeights weights, ContextAnalyzer.APIContext apiContext) {
        if (weights == null || weights.getContextMultipliers() == null || apiContext == null) {
            return 1.0;
        }
        return weights.getContextMultipliers()
            .getOrDefault(apiContext.name().toLowerCase(Locale.ROOT), 1.0);
    }
}

