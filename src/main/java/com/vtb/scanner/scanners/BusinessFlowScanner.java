package com.vtb.scanner.scanners;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * API6:2023 - Unrestricted Access to Sensitive Business Flows
 * Проверяет отсутствие защиты бизнес-процессов от автоматизации и злоупотреблений
 */
@Slf4j
public class BusinessFlowScanner implements VulnerabilityScanner {
    
    private final String targetUrl;
    private final com.vtb.scanner.config.ScannerConfig config;
    private final List<String> sensitiveOperations;
    private final List<String> protectionKeywords;
    
    public BusinessFlowScanner(String targetUrl) {
        this.targetUrl = targetUrl;
        
        // Используем конфигурацию вместо хардкода!
        this.config = com.vtb.scanner.config.ScannerConfig.load();
        
        // Собираем все операции из конфига
        this.sensitiveOperations = new ArrayList<>();
        if (config.getSensitiveOperations() != null) {
            config.getSensitiveOperations().values().forEach(sensitiveOperations::addAll);
        }
        
        this.protectionKeywords = config.getProtectionKeywords() != null ? 
            config.getProtectionKeywords() : new ArrayList<>();
    }
    
    @Override
    public List<Vulnerability> scan(OpenAPI openAPI, OpenAPIParser parser) {
        log.info("Запуск Business Flow Scanner (API6:2023)...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // Проверяем ВСЕ методы HTTP!
            if (pathItem.getGet() != null) {
                vulnerabilities.addAll(checkBusinessFlow(path, "GET", pathItem.getGet(), parser));
            }
            if (pathItem.getPost() != null) {
                vulnerabilities.addAll(checkBusinessFlow(path, "POST", pathItem.getPost(), parser));
            }
            if (pathItem.getPut() != null) {
                vulnerabilities.addAll(checkBusinessFlow(path, "PUT", pathItem.getPut(), parser));
            }
            if (pathItem.getDelete() != null) {
                vulnerabilities.addAll(checkBusinessFlow(path, "DELETE", pathItem.getDelete(), parser));
            }
            if (pathItem.getPatch() != null) {
                vulnerabilities.addAll(checkBusinessFlow(path, "PATCH", pathItem.getPatch(), parser));
            }
        }
        
        log.info("Business Flow Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private List<Vulnerability> checkBusinessFlow(String path, String method, Operation operation,
                                                   OpenAPIParser parser) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // ИСПОЛЬЗУЕМ SmartAnalyzer для контекста!
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(
            path, method, operation, parser.getOpenAPI());
        Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
        
        // СЕМАНТИЧЕСКИЙ АНАЛИЗ - точнее определяем тип!
        com.vtb.scanner.semantic.OperationClassifier.OperationType opType = 
            com.vtb.scanner.semantic.OperationClassifier.classify(path, method, operation);
        
        boolean isFinancial = (opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.TRANSFER_MONEY ||
                              opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.PAYMENT ||
                              opType == com.vtb.scanner.semantic.OperationClassifier.OperationType.WITHDRAWAL);
        
        boolean isSensitiveOperation = isSensitiveBusinessOperation(path, operation);
        
        if (!isSensitiveOperation) {
            return vulnerabilities;
        }
        
        String lowerPath = path != null ? path.toLowerCase(Locale.ROOT) : "";
        boolean isCatalogFlow = lowerPath.contains("/products") || lowerPath.contains("catalog");

        if (isCatalogFlow && "GET".equalsIgnoreCase(method)) {
            return vulnerabilities;
        }

        boolean hasProtection = hasAutomationProtection(operation);
        boolean hasRateLimit = hasRateLimitProtection(operation);
        boolean requiresAuth = parser.requiresAuthentication(operation);
        
        // 1. Критичная операция без защиты от автоматизации
        if (!hasProtection && !hasRateLimit) {
            // УМНЫЙ расчёт: SmartAnalyzer + семантика
            Severity severity;
            if (isFinancial) {
                // Финансовые операции - критичнее!
                severity = (baseSeverity == Severity.CRITICAL || riskScore > 120) ? 
                    Severity.CRITICAL : Severity.HIGH;
            } else if (requiresAuth) {
                severity = switch(baseSeverity) {
                    case CRITICAL, HIGH -> Severity.MEDIUM;
                    case MEDIUM -> Severity.MEDIUM;
                    default -> baseSeverity;
                };
            } else {
                // Нет auth - повышаем
                severity = switch(baseSeverity) {
                    case INFO, LOW -> Severity.MEDIUM;
                    case MEDIUM -> Severity.HIGH;
                    case HIGH, CRITICAL -> baseSeverity;
                };
            }
            
            // ДИНАМИЧЕСКИЙ расчет!
            Vulnerability tempVuln = Vulnerability.builder()
                .type(VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW)
                .severity(severity)
                .riskScore(riskScore)
                .build();
            
            int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(
                tempVuln, operation, false, true); // hasEvidence=true (нашли чувствительную операцию!)
            
            // Для финансовых - повышаем уверенность
            if (isFinancial) {
                confidence = Math.min(100, confidence + 20);
            }
            
            int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                tempVuln, confidence);
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW, path, method, null,
                    "No automation protection"))
                .type(VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW)
                .severity(severity)
                .riskScore(riskScore)
                .title("Критичная бизнес-операция без защиты от автоматизации")
                .confidence(confidence)
                .priority(priority)
                .impactLevel(isFinancial ? "FINANCIAL_FRAUD: Автоматизированное мошенничество" : "ABUSE: Автоматизация атак")
                .description(String.format(
                    "Эндпоинт %s %s выполняет чувствительную операцию, но не защищен от:\n" +
                    "• Автоматизированных атак (ботов)\n" +
                    "• Mass requests\n" +
                    "• Скриптов для злоупотреблений\n\n" +
                    "Злоумышленник может использовать скрипт для множественных операций.",
                    method, path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Добавьте защиту от автоматизации:\n" +
                    "1. CAPTCHA/reCAPTCHA для критичных операций\n" +
                    "2. Rate limiting (например, 5 операций в минуту)\n" +
                    "3. Требование дополнительной верификации (OTP, 2FA)\n" +
                    "4. Monitoring подозрительной активности\n" +
                    "5. Device fingerprinting\n" +
                    "6. Временные блокировки при подозрительном поведении"
                )
                .owaspCategory("API6:2023 - Unrestricted Access to Sensitive Business Flows")
                .evidence("Чувствительная операция без CAPTCHA/rate limit/verification. Risk Score: " + riskScore)
                .build());
        }
        
        // 2. Операции с деньгами без дополнительной верификации
        if (!isCatalogFlow &&
            isMoneyOperation(path, operation) && !"GET".equalsIgnoreCase(method) && !hasTwoFactorAuth(operation)) {
            // Для финансовых операций - используем SmartAnalyzer!
            Severity severity;
            if (requiresAuth) {
                severity = Severity.MEDIUM;
            } else if (isFinancial) {
                severity = (baseSeverity == Severity.CRITICAL || riskScore > 120) ?
                    Severity.HIGH : Severity.MEDIUM;
            } else {
                severity = Severity.MEDIUM;
            }
            
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW, path, method, null,
                    "Money operation without protection"))
                .type(VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW)
                .severity(severity)
                .riskScore(riskScore)
                .title("Финансовая операция без 2FA")
                .description(String.format(
                    "Эндпоинт %s выполняет операцию с деньгами, но не требует:\n" +
                    "• Двухфакторной аутентификации (2FA/MFA)\n" +
                    "• OTP кодов\n" +
                    "• Дополнительного подтверждения\n\n" +
                    "При компрометации сессии злоумышленник может совершить платеж.",
                    path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Для финансовых операций обязательно:\n" +
                    "• Требовать 2FA/MFA\n" +
                    "• Отправлять OTP на телефон/email\n" +
                    "• Подтверждение через мобильное приложение\n" +
                    "• Transaction signing"
                )
                .owaspCategory("API6:2023 - Unrestricted Access to Sensitive Business Flows")
                .evidence("Платеж/перевод без 2FA")
                .build());
        }
        
        // 3. Голосование/рейтинги без защиты
        if (isVotingOperation(path, operation) && !hasProtection) {
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW, path, method, null,
                    "Voting operation without protection"))
                .type(VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW)
                .severity(Severity.MEDIUM)
                .title("Голосование/рейтинг без защиты от накрутки")
                .description(String.format(
                    "Эндпоинт %s позволяет голосовать/оценивать без защиты.\n" +
                    "Возможна накрутка рейтингов через скрипты.",
                    path
                ))
                .endpoint(path)
                .method(method)
                .recommendation(
                    "Защитите систему голосования:\n" +
                    "• 1 голос с 1 IP/аккаунта за период\n" +
                    "• CAPTCHA при подозрительной активности\n" +
                    "• Требование verified аккаунта\n" +
                    "• Временные ограничения между голосами"
                )
                .owaspCategory("API6:2023 - Unrestricted Access to Sensitive Business Flows")
                .evidence("Голосование без rate limit")
                .build());
        }
        
        return vulnerabilities;
    }
    
    private boolean isSensitiveBusinessOperation(String path, Operation operation) {
        String text = path.toLowerCase() + " " +
                     (operation.getSummary() != null ? operation.getSummary().toLowerCase() : "") + " " +
                     (operation.getDescription() != null ? operation.getDescription().toLowerCase() : "");
        
        // Используем конфиг вместо хардкода!
        return sensitiveOperations.stream().anyMatch(text::contains);
    }
    
    private boolean hasAutomationProtection(Operation operation) {
        String text = (operation.getDescription() != null ? operation.getDescription() : "") +
                     (operation.getSummary() != null ? operation.getSummary() : "");
        String lower = text.toLowerCase();
        
        // Используем конфиг вместо хардкода!
        return protectionKeywords.stream().anyMatch(lower::contains);
    }
    
    private boolean hasRateLimitProtection(Operation operation) {
        if (operation.getResponses() != null && operation.getResponses().get("429") != null) {
            return true;
        }
        
        String text = (operation.getDescription() != null ? operation.getDescription() : "").toLowerCase();
        return text.contains("rate limit") || text.contains("throttle");
    }
    
    private boolean isMoneyOperation(String path, Operation operation) {
        String text = path.toLowerCase() + " " +
                     (operation.getSummary() != null ? operation.getSummary().toLowerCase() : "") + " " +
                     (operation.getDescription() != null ? operation.getDescription().toLowerCase() : "");
        
        return text.contains("payment") || text.contains("pay") || 
               text.contains("transfer") || text.contains("withdraw") ||
               text.contains("deposit") || text.contains("purchase") ||
               text.contains("checkout");
    }
    
    private boolean isVotingOperation(String path, Operation operation) {
        String text = path.toLowerCase() + " " +
                     (operation.getSummary() != null ? operation.getSummary().toLowerCase() : "");
        
        return text.contains("vote") || text.contains("rating") || 
               text.contains("review") || text.contains("like");
    }
    
    private boolean hasTwoFactorAuth(Operation operation) {
        String text = (operation.getDescription() != null ? operation.getDescription() : "").toLowerCase();
        return text.contains("2fa") || text.contains("mfa") || 
               text.contains("otp") || text.contains("two-factor") ||
               text.contains("two factor");
    }
}

