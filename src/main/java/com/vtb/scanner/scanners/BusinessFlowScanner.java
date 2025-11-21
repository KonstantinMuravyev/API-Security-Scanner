package com.vtb.scanner.scanners;

import com.vtb.scanner.config.ScannerConfig;
import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.analysis.SchemaConstraintAnalyzer;
import com.vtb.scanner.analysis.SchemaConstraintAnalyzer.SchemaConstraints;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.semantic.ContextAnalyzer;
import com.vtb.scanner.semantic.OperationClassifier;
import com.vtb.scanner.semantic.OperationClassifier.OperationType;
import com.vtb.scanner.util.AccessControlHeuristics;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.Schema;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import io.swagger.v3.oas.models.parameters.Parameter;

/**
 * API6:2023 - Unrestricted Access to Sensitive Business Flows
 * Проверяет отсутствие защиты бизнес-процессов от автоматизации и злоупотреблений
 */
@Slf4j
public class BusinessFlowScanner implements VulnerabilityScanner {
    
    private final String targetUrl;
    private final ScannerConfig config;
    private final ScannerConfig.FeatureToggles featureToggles;
    private final List<String> sensitiveOperations;
    private final List<String> protectionKeywords;
    
    public BusinessFlowScanner(String targetUrl) {
        this.targetUrl = targetUrl;
        
        // Используем конфигурацию вместо хардкода!
        this.config = ScannerConfig.load();
        this.featureToggles = this.config.getFeatureToggles() != null
            ? this.config.getFeatureToggles()
            : new ScannerConfig.FeatureToggles();
        
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
        log.info("Запуск Business Flow Scanner (API6:2023) для {}", targetUrl);
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        Set<String> typeDedup = new HashSet<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        SchemaConstraintAnalyzer constraintAnalyzer = new SchemaConstraintAnalyzer(openAPI);
        Set<String> dedupe = new HashSet<>();
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // Проверяем ВСЕ методы HTTP!
            if (pathItem.getGet() != null) {
                vulnerabilities.addAll(checkBusinessFlow(path, "GET", pathItem.getGet(), parser, dedupe, typeDedup,
                    pathItem.getParameters(), constraintAnalyzer));
            }
            if (pathItem.getPost() != null) {
                vulnerabilities.addAll(checkBusinessFlow(path, "POST", pathItem.getPost(), parser, dedupe, typeDedup,
                    pathItem.getParameters(), constraintAnalyzer));
            }
            if (pathItem.getPut() != null) {
                vulnerabilities.addAll(checkBusinessFlow(path, "PUT", pathItem.getPut(), parser, dedupe, typeDedup,
                    pathItem.getParameters(), constraintAnalyzer));
            }
            if (pathItem.getDelete() != null) {
                vulnerabilities.addAll(checkBusinessFlow(path, "DELETE", pathItem.getDelete(), parser, dedupe, typeDedup,
                    pathItem.getParameters(), constraintAnalyzer));
            }
            if (pathItem.getPatch() != null) {
                vulnerabilities.addAll(checkBusinessFlow(path, "PATCH", pathItem.getPatch(), parser, dedupe, typeDedup,
                    pathItem.getParameters(), constraintAnalyzer));
            }
        }
        
        log.info("Business Flow Scanner завершен. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private List<Parameter> combineParameters(List<Parameter> inheritedParameters, Operation operation) {
        List<Parameter> all = new ArrayList<>();
        if (inheritedParameters != null) {
            for (Parameter parameter : inheritedParameters) {
                if (parameter != null) {
                    all.add(parameter);
                }
            }
        }
        if (operation != null && operation.getParameters() != null) {
            for (Parameter parameter : operation.getParameters()) {
                if (parameter != null) {
                    all.add(parameter);
                }
            }
        }
        return all;
    }

    private FlowSchemaSignals collectFlowSchemaSignals(List<Parameter> parameters,
                                                       Operation operation,
                                                       SchemaConstraintAnalyzer constraintAnalyzer,
                                                       OpenAPI openAPI) {
        if (constraintAnalyzer == null) {
            return FlowSchemaSignals.empty();
        }
        FlowSchemaSignals.Builder builder = FlowSchemaSignals.builder();

        if (parameters != null) {
            for (Parameter parameter : parameters) {
                if (parameter == null || parameter.getName() == null) {
                    continue;
                }
                String name = parameter.getName();
                String in = parameter.getIn() != null ? parameter.getIn() : "param";
                SchemaConstraints constraints = constraintAnalyzer.analyzeParameter(parameter);
                builder.registerGuard(constraints);
                considerSchemaSignal(builder,
                    "param." + in + "." + name,
                    name,
                    parameter.getDescription(),
                    constraints);
            }
        }

        if (operation != null && operation.getRequestBody() != null &&
            operation.getRequestBody().getContent() != null) {
            operation.getRequestBody().getContent().forEach((mediaType, media) -> {
                if (media == null || media.getSchema() == null) {
                    return;
                }
                collectFlowSchemaSignalsFromSchema(
                    media.getSchema(),
                    constraintAnalyzer,
                    new HashSet<>(),
                    "$",
                    builder);
            });
        }

        if (openAPI != null && openAPI.getComponents() != null && openAPI.getComponents().getSecuritySchemes() != null) {
            openAPI.getComponents().getSecuritySchemes().forEach((name, scheme) -> {
                if (name == null || scheme == null) {
                    return;
                }
                String lower = name.toLowerCase(Locale.ROOT);
                if (isCaptchaIndicator(lower) || containsKeyword(scheme.getDescription(), CAPTCHA_TEXT_KEYWORDS)) {
                    builder.markCaptcha("securityScheme." + name, null);
                }
            });
        }

        return builder.build();
    }

    private void collectFlowSchemaSignalsFromSchema(Schema<?> schema,
                                                    SchemaConstraintAnalyzer constraintAnalyzer,
                                                    Set<Schema<?>> visited,
                                                    String pointer,
                                                    FlowSchemaSignals.Builder builder) {
        if (schema == null || constraintAnalyzer == null) {
            return;
        }
        if (!visited.add(schema)) {
            return;
        }

        SchemaConstraints constraints = constraintAnalyzer.analyzeSchema(schema);
        builder.registerGuard(constraints);
        Map<String, Schema<?>> properties = castSchemaMap(schema.getProperties());
        if (properties != null) {
            for (Map.Entry<String, Schema<?>> entry : properties.entrySet()) {
                Schema<?> child = entry.getValue();
                if (child == null) {
                    continue;
                }
                String propertyName = entry.getKey();
                String propertyPointer = pointer + "." + propertyName;
                SchemaConstraints childConstraints = constraintAnalyzer.analyzeSchema(child);
                considerSchemaSignal(builder,
                    "body" + propertyPointer,
                    propertyName,
                    child.getDescription(),
                    childConstraints);
                collectFlowSchemaSignalsFromSchema(child, constraintAnalyzer, new HashSet<>(visited), propertyPointer, builder);
            }
        }

        if (schema.getAllOf() != null) {
            for (Schema<?> sub : schema.getAllOf()) {
                collectFlowSchemaSignalsFromSchema(sub, constraintAnalyzer, new HashSet<>(visited), pointer, builder);
            }
        }
        if (schema.getOneOf() != null) {
            int index = 0;
            for (Schema<?> sub : schema.getOneOf()) {
                collectFlowSchemaSignalsFromSchema(sub, constraintAnalyzer, new HashSet<>(visited), pointer + ".oneOf[" + index + "]", builder);
                index++;
            }
        }
        if (schema.getAnyOf() != null) {
            int index = 0;
            for (Schema<?> sub : schema.getAnyOf()) {
                collectFlowSchemaSignalsFromSchema(sub, constraintAnalyzer, new HashSet<>(visited), pointer + ".anyOf[" + index + "]", builder);
                index++;
            }
        }

        if (schema.getItems() != null) {
            collectFlowSchemaSignalsFromSchema(schema.getItems(), constraintAnalyzer, new HashSet<>(visited), pointer + "[]", builder);
        }

        if (!schemaSignalsRelevant(constraints)) {
            String basePointer = "$".equals(pointer) ? "body.$" : "body" + pointer;
            builder.addEvidence(basePointer, constraints);
        }
    }

    private boolean schemaSignalsRelevant(SchemaConstraints constraints) {
        return constraints != null && (constraints.getGuardStrength() == SchemaConstraints.GuardStrength.STRONG
            || constraints.getGuardStrength() == SchemaConstraints.GuardStrength.NOT_USER_CONTROLLED);
    }

    private void considerSchemaSignal(FlowSchemaSignals.Builder builder,
                                      String location,
                                      String rawName,
                                      String description,
                                      SchemaConstraints constraints) {
        if (rawName == null) {
            return;
        }
        builder.registerGuard(constraints);
        String lowerName = rawName.toLowerCase(Locale.ROOT);
        boolean matched = false;
        if (isCaptchaIndicator(lowerName) || containsKeyword(description, CAPTCHA_TEXT_KEYWORDS)) {
            builder.markCaptcha(location, constraints);
            matched = true;
        }
        if (isDeviceIndicator(lowerName) || containsKeyword(description, DEVICE_TEXT_KEYWORDS)) {
            builder.markDevice(location, constraints);
            matched = true;
        }
        if (!matched && constraints != null && !constraints.isUserControlled()) {
            builder.addEvidence(location, constraints);
        }
    }

    private List<Vulnerability> checkBusinessFlow(String path, String method, Operation operation,
                                                  OpenAPIParser parser,
                                                  Set<String> dedupe,
                                                  Set<String> typeDedup,
                                                  List<Parameter> inheritedParameters,
                                                  SchemaConstraintAnalyzer constraintAnalyzer) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (operation == null) {
            return vulnerabilities;
        }
        OpenAPI openAPI = parser != null ? parser.getOpenAPI() : null;
        List<Parameter> allParameters = combineParameters(inheritedParameters, operation);
        FlowSchemaSignals schemaSignals = collectFlowSchemaSignals(allParameters, operation, constraintAnalyzer, openAPI);
        List<String> schemaEvidence = schemaSignals.evidenceNotes();
        int riskScore = com.vtb.scanner.heuristics.SmartAnalyzer.calculateRiskScore(path, method, operation, openAPI);
        int mitigation = schemaSignals.guardMitigationScore();
        if (schemaSignals.hasCaptcha) {
            mitigation += 12;
        }
        if (schemaSignals.hasDeviceField) {
            mitigation += 8;
        }
        if (mitigation > 0) {
            riskScore = Math.max(0, riskScore - Math.min(mitigation, 40));
        }
        Severity baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);
 
        // СЕМАНТИЧЕСКИЙ АНАЛИЗ - точнее определяем тип!
        OperationType opType = OperationClassifier.classify(path, method, operation);
        
        boolean isFinancial = (opType == OperationType.TRANSFER_MONEY ||
                              opType == OperationType.PAYMENT ||
                              opType == OperationType.WITHDRAWAL);
        
        boolean isSensitiveOperation = isSensitiveBusinessOperation(path, operation);
        
        if (!isSensitiveOperation) {
            return vulnerabilities;
        }
        
        String lowerPath = path != null ? path.toLowerCase(Locale.ROOT) : "";
        String combinedText = buildCombinedText(path, operation);
        boolean isPasswordResetFlow = lowerPath.contains("password") &&
            (lowerPath.contains("reset") || lowerPath.contains("recover") || lowerPath.contains("restore") ||
                combinedText.contains("password reset") || combinedText.contains("forgot password"));
        boolean isCatalogFlow = lowerPath.contains("/products") || lowerPath.contains("catalog");
        boolean isMarketplaceFlow = isMarketplaceOperation(combinedText);
        boolean isMarketplaceRefund = isMarketplaceRefundOperation(combinedText);
        boolean isMarketplacePayout = isMarketplacePayoutOperation(combinedText);
        boolean isMerchantOnboarding = isMerchantOnboardingOperation(combinedText);
        boolean isGovernmentService = isGovernmentServiceOperation(combinedText);
        boolean isTelecomOperation = isTelecomOperation(combinedText);
        boolean isTelecomCritical = isTelecomCriticalOperation(combinedText);
        boolean isConnectedCarOperation = isConnectedCarOperation(combinedText);
        boolean isRemoteVehicleControl = isRemoteVehicleControlOperation(combinedText);
        boolean isOtaFlow = isOtaOperation(combinedText);

        if (isCatalogFlow && "GET".equalsIgnoreCase(method)) {
            return vulnerabilities;
        }

        boolean hasProtection = hasAutomationProtection(operation, schemaSignals);
        boolean hasRateLimit = hasRateLimitProtection(operation);
        boolean requiresAuth = parser != null && parser.requiresAuthentication(operation);
        boolean hasFraudControls = hasFraudMonitoring(operation);
        boolean hasIdentityVerification = hasIdentityVerification(operation);
        boolean hasApprovalProcess = hasApprovalFlow(operation);
        boolean hasDeviceFingerprint = hasDeviceFingerprint(operation);
        boolean hasBehaviorAnalytics = hasBehaviorAnalytics(operation);
        boolean hasSchemaDeviceFingerprint = schemaSignals.hasDeviceField;
        if (hasSchemaDeviceFingerprint) {
            hasDeviceFingerprint = true;
        }
        if (schemaSignals.hasCaptcha) {
            hasProtection = true;
        }
        boolean hasStrongAuthorization = AccessControlHeuristics.hasStrongAuthorization(operation, openAPI);
        boolean hasExplicitAccess = AccessControlHeuristics.hasExplicitAccessControl(operation, path, openAPI);
        boolean hasConsentEvidence = AccessControlHeuristics.hasConsentEvidence(operation, openAPI);
        boolean isOpenBankingOperation = AccessControlHeuristics.isOpenBankingOperation(path, operation, openAPI);

        ContextAnalyzer.APIContext apiContext = ContextAnalyzer.detectContext(openAPI);
        boolean highContext = apiContext == ContextAnalyzer.APIContext.BANKING ||
            apiContext == ContextAnalyzer.APIContext.GOVERNMENT ||
            apiContext == ContextAnalyzer.APIContext.HEALTHCARE;
        boolean telecomContext = apiContext == ContextAnalyzer.APIContext.TELECOM;
        boolean automotiveContext = apiContext == ContextAnalyzer.APIContext.AUTOMOTIVE;

        riskScore = applyRiskWeights(riskScore, operation, apiContext, isMarketplaceFlow, isGovernmentService, hasConsentEvidence);
        baseSeverity = com.vtb.scanner.heuristics.SmartAnalyzer.severityFromRiskScore(riskScore);

        boolean isHighValueOperation = HIGH_VALUE_OPERATION_KEYWORDS.stream().anyMatch(combinedText::contains);
        boolean isBulkOperation = BULK_OPERATION_KEYWORDS.stream().anyMatch(combinedText::contains);
        boolean isLoanOperation = LOAN_OPERATION_KEYWORDS.stream().anyMatch(combinedText::contains);

        if (featureToggles.marketplaceEnabled() && isMarketplaceFlow && !hasStrongAuthorization && !hasExplicitAccess) {
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Оформление заказа без аутентификации",
                "Эндпоинт обслуживает оформление заказа/корзины, но не требует аутентификации. " +
                    "Злоумышленник может оформлять заказы от имени других клиентов или автоматизировать бот-атаки.",
                !hasProtection ? "Добавьте авторизацию, CAPTCHA и rate limiting." : "Добавьте авторизацию и токены сессии." ,
                Severity.HIGH,
                "ORDER_FLOW: Маркетплейс без аутентификации",
                dedupe,
                schemaEvidence);
        }

        if (featureToggles.marketplaceEnabled() && featureToggles.fraudHeuristicsEnabled() &&
            isMarketplaceFlow && !hasProtection && !hasRateLimit && !hasFraudControls) {
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Маркетплейс операция без защиты от накрутки",
                "Чувствительная операция маркетплейса (заказ/корзина) не имеет защиты от ботов (нет CAPTCHA, rate limiting, anti-fraud мониторинга).",
                "Добавьте CAPTCHA, динамический rate limiting, velocity-checkи и антифрод логику (device fingerprint, риск-скоринг).",
                Severity.HIGH,
                "MARKETPLACE_ABUSE: Отсутствует антифрод",
                dedupe,
                schemaEvidence);
        }

        if (featureToggles.marketplaceEnabled() && featureToggles.fraudHeuristicsEnabled() &&
            isMarketplaceRefund && !hasApprovalProcess) {
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Возвраты без ручного или автоматизированного одобрения",
                "Эндпоинт обрабатывает возвраты/refund, но в спецификации отсутствует упоминание ручного или автоматизированного процесса одобрения.",
                "Добавьте workflow: manual review, risk score, подтверждение менеджера перед возвратом средств.",
                Severity.HIGH,
                "REFUND_FLOW: Нет этапа одобрения",
                dedupe,
                schemaEvidence);
        }

        if (featureToggles.marketplaceEnabled() && isMarketplacePayout && !hasTwoFactorAuth(operation, openAPI)) {
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Выплаты мерчантам без усиленной аутентификации",
                "Эндпоинт управляет выплатами/settlement продавцам, но не требует 2FA/OTP. Компрометация сессии приведёт к выводу средств.",
                "Добавьте 2FA (OTP, подпись), привязку устройства и контроль лимитов перед вынесением платежей.",
                Severity.HIGH,
                "PAYOUT_FLOW: Нет 2FA",
                dedupe,
                schemaEvidence);
        }

        if (featureToggles.marketplaceEnabled() && isMerchantOnboarding && !hasIdentityVerification) {
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Онбординг мерчанта без проверки личности",
                "Онбординг/регистрация продавца не описывает KYC/документальную проверку. Мошенники смогут массово регистрировать магазины.",
                "Добавьте KYC/KYB процессы: загрузку документов, проверку ИНН/регистрации, ручное одобрение.",
                Severity.HIGH,
                "ONBOARDING_FLOW: Нет KYC",
                dedupe,
                schemaEvidence);
        }

        if (featureToggles.marketplaceEnabled() && featureToggles.fraudHeuristicsEnabled() &&
            isMerchantOnboarding && !hasApprovalProcess) {
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Онбординг без этапа одобрения",
                "Процесс подключения продавца не содержит упоминаний об одобрении (manual review/compliance).",
                "Реализуйте мультиэтапное одобрение (compliance, risk, legal) перед активацией аккаунта.",
                Severity.MEDIUM,
                "ONBOARDING_FLOW: Нет review",
                dedupe,
                schemaEvidence);
        }

        if ((telecomContext || isTelecomOperation) && !hasSimBindingEvidence(operation)) {
            Severity severity = (telecomContext || isTelecomCritical) ? Severity.CRITICAL : Severity.HIGH;
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Телефония/мобильный сервис без SIM/устройственного биндинга",
                "Чувствительная операция (смена тарифа, управление msisdn/sim) не описывает привязку к устройству/SIM. " +
                    "Компрометация аккаунта позволит злоумышленнику переоформить номер или подключить услуги.",
                "Добавьте SIM/Device binding: X-PSU-Device-ID, trusted SIM, проверку IMSI/ICCID, ручное подтверждение смены SIM/тарифа.",
                severity,
                "TELECOM_FLOW: Нет SIM binding",
                dedupe,
                schemaEvidence);
        }

        if ((telecomContext || isTelecomOperation) && !hasTwoFactorAuth(operation, openAPI)) {
            Severity severity = isTelecomCritical ? Severity.CRITICAL : Severity.HIGH;
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Критичная телеком-операция без 2FA/OTP",
                "Операция управления номером/тарифом/roaming выполняется без многофакторной проверки. Это позволяет захватить номер или включить платные услуги.",
                "Добавьте OTP/2FA, подтверждение в мобильном приложении или call-back при изменении msisdn/сим/тарифа.",
                severity,
                "TELECOM_FLOW: Нет 2FA",
                dedupe,
                schemaEvidence);
        }

        if ((telecomContext || isTelecomOperation) && isTelecomCritical && !hasFraudControls) {
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Телеком критичная операция без антифрода",
                "Операция (SIM swap, transfer, roaming) не описывает антифрод/velocity-check. Это позволяет злоумышленнику массово переключать тарифы или похищать номера.",
                "Добавьте anti-fraud: мониторинг запросов, velocity-check, ручное подтверждение SIM swap, уведомления владельцу.",
                Severity.HIGH,
                "TELECOM_FLOW: Нет антифрода",
                dedupe,
                schemaEvidence);
        }

        if ((automotiveContext || isConnectedCarOperation) && isRemoteVehicleControl && !hasTwoFactorAuth(operation, openAPI)) {
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Дистанционное управление автомобилем без 2FA",
                "Эндпоинт позволяет управлять функциями автомобиля (unlock, start, climate), но не требует 2FA/OTP. " +
                    "Угонщик может использовать украденные учётные данные для удалённого открытия/запуска авто.",
                "Добавьте обязательный OTP/2FA, подтверждение в мобильном приложении, геофенсинг и уведомления владельцу.",
                Severity.CRITICAL,
                "VEHICLE_CONTROL: Нет 2FA",
                dedupe,
                schemaEvidence);
        }

        if (isOpenBankingOperation && (!hasConsentEvidence || !hasStrongAuthorization) && !hasExplicitAccess) {
            List<String> missingControls = new ArrayList<>();
            if (!hasStrongAuthorization) {
                missingControls.add("Authorization Bearer/TPP токены");
            }
            if (!hasConsentEvidence) {
                missingControls.add("consent headers/permissions");
            }
            String missingDesc = missingControls.isEmpty() ? "consent enforcement" : String.join(", ", missingControls);
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Open Banking операция без строгого контроля",
                "Open Banking/PSD2 операция не содержит явных признаков обязательных механизмов: " + missingDesc + ". " +
                    "Это допускает выполнение платежей или выдачу данных без подтверждённого согласия клиента.",
                "Опишите в спецификации OAuth2 scopes, обязательные заголовки x-consent-id/x-requesting-bank, PSU/TPP идентификаторы и проверку токенов. " +
                    "Без этого возможны обходы согласия и регуляторные нарушения.",
                Severity.CRITICAL,
                "OPEN_BANKING: Нет consent/authorization",
                dedupe,
                schemaEvidence);
        }

        if ((automotiveContext || isConnectedCarOperation) && isOtaFlow && !hasOtaIntegrityEvidence(operation)) {
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "OTA/firmware обновление без подписи и проверок целостности",
                "OTA/firmware эндпоинт не описывает подпись, hash/проверку целостности, secure boot. " +
                    "Злоумышленник может внедрить вредоносную прошивку и получить контроль над транспортом.",
                "Требуйте цифровую подпись firmware (ГОСТ/Pkcs7), проверку hash, secure boot, журналирование и ручное подтверждение критичных OTA.",
                Severity.HIGH,
                "CONNECTED_CAR: OTA без подписи",
                dedupe,
                schemaEvidence);
        }

        if ((automotiveContext || isConnectedCarOperation) && !hasBehaviorAnalytics(operation)) {
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Connected car сервис без мониторинга аномалий",
                "Операция телематики/connected car не описывает антифрод/анализ поведения. Атака может отправлять массовые команды (unlock/engine start).",
                "Добавьте телематику-антифрод: velocity-check, геофенсинг, контроль расписаний, ручной review подозрительных команд.",
                Severity.HIGH,
                "CONNECTED_CAR: Нет антифрода",
                dedupe,
                schemaEvidence);
        }

        if (featureToggles.governmentEnabled() && isGovernmentService && !hasIdentityVerification) {
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Госуслуга без подтверждения личности",
                "Операция связана с госуслугами, но отсутствуют признаки верификации личности (паспорт, ЭЦП, ЕСИА).",
                "Подключите подтверждение личности: ЭЦП, госидентификатор, проверку документов",
                Severity.CRITICAL,
                "GOV_FLOW: Нет идентификации",
                dedupe,
                schemaEvidence);
        }

        if (featureToggles.governmentEnabled() && featureToggles.fraudHeuristicsEnabled() &&
            isGovernmentService && !hasApprovalProcess) {
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Госуслуга без многоуровневой проверки",
                "Процедура госуслуги не описывает этапов ручной проверки/решения должностного лица.",
                "Добавьте описание workflow: статус заявки, ответственные роли, уведомления о решении.",
                Severity.HIGH,
                "GOV_FLOW: Нет approval",
                dedupe,
                schemaEvidence);
        }

        if (featureToggles.loginRateLimitEnabled() && (opType == OperationType.LOGIN ||
            opType == OperationType.REGISTER) &&
            !hasRateLimit && !hasProtection) {
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Login/регистрация без защиты от перебора",
                "Операция входа/регистрации не описывает rate limiting или CAPTCHA. Это позволяет перебор паролей и массовые регистрации.",
                "Добавьте rate limiting, CAPTCHA/дополнительную проверку и блокировки при превышении порога ошибок.",
                Severity.HIGH,
                "AUTH_ABUSE: Нет rate limiting",
                dedupe,
                schemaEvidence);
        }

        boolean mentionsConsent = AccessControlHeuristics.mentionsPersonalData(operation) ||
            CONSENT_EXPECTATION_KEYWORDS.stream().anyMatch(combinedText::contains);
        if (featureToggles.consentEnabled() && mentionsConsent && !hasConsentEvidence) {
            Severity consentSeverity = highContext ? Severity.CRITICAL : Severity.HIGH;
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Операция с персональными данными без consent-механизма",
                "Эндпоинт оперирует персональными данными/consent, но в спецификации нет признаков consent ID, scope или подтверждения пользователя.",
                "Добавьте явный consent workflow: заголовок X-Consent-Id, список permissions, audit trail. Без этого API нарушает требования приватности.",
                consentSeverity,
                "CONSENT_FLOW: Нет подтверждения",
                dedupe,
                schemaEvidence);
        }

        if (featureToggles.sessionHardeningEnabled() && isSessionOperation(combinedText, method) && !hasSessionHardening(operation)) {
            Severity sessionSeverity = highContext ? Severity.HIGH : Severity.MEDIUM;
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Сессионное управление без защиты",
                "Операция управляет сессиями/токенами, но не описывает истечение, отзыв или ротацию. Это повышает риск фиксации сессии.",
                "Задокументируйте истечение сессий, механизмы revoke/invalidate, rotation refresh-токенов и ограничение количества активных сессий.",
                sessionSeverity,
                "SESSION_FLOW: Нет hardening",
                dedupe,
                schemaEvidence);
        }

        if (featureToggles.fraudHeuristicsEnabled() && (isHighValueOperation || isBulkOperation)) {
            boolean missing2fa = !hasTwoFactorAuth(operation, openAPI);
            boolean missingApproval = !hasApprovalProcess;
            if (missing2fa || missingApproval) {
                Severity dualControlSeverity = missing2fa && missingApproval ? Severity.CRITICAL : Severity.HIGH;
                addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                    "Высокорисковая финансовая операция без dual control",
                    "Эндпоинт выполняет высокорисковую операцию (массовые платежи/treasury/bulk transfer), но отсутствует dual control: " +
                        (missing2fa ? "нет 2FA/OTP. " : "") +
                        (missingApproval ? "нет ручного или автоматизированного одобрения. " : "") +
                        "Компрометация учетных данных позволит вывести крупные суммы.",
                    "Внедрите dual control: обязательный OTP/2FA, лимиты по сумме, подтверждение вторым сотрудником, " +
                        "velocity-check и мониторинг аномалий.",
                    dualControlSeverity,
                    "TREASURY_FLOW: Нет dual control",
                    dedupe,
                    schemaEvidence);
            }
        }

        if (featureToggles.fraudHeuristicsEnabled() && isLoanOperation && !hasFraudControls && !hasBehaviorAnalytics) {
            Severity loanSeverity = highContext ? Severity.HIGH : Severity.MEDIUM;
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Кредитный/loan процесс без скоринга и антифрода",
                "Операция связана с кредитами/loan issuance, но отсутствуют признаки скоринга, риск-аналитики или антифрод-контроля. " +
                    "Мошенник может оформить кредит без проверки платежеспособности.",
                "Добавьте скоринг/риск-оценку, антифрод-проверки (AML/KYC), ручное подтверждение крупных кредитов.",
                loanSeverity,
                "LOAN_FLOW: Нет скоринга",
                dedupe,
                schemaEvidence);
        }

        if (featureToggles.loginRateLimitEnabled() && isPasswordResetFlow &&
            !hasTwoFactorAuth(operation, openAPI) && !hasRateLimit) {
            addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity,
                "Восстановление пароля без защиты",
                "Процесс восстановления/сброса пароля не содержит OTP/2FA и rate limiting. Это позволяет брутфорсить одноразовые коды и массово перехватывать аккаунты.",
                "Добавьте обязательный OTP/2FA, rate limiting, временную блокировку после нескольких неудачных попыток и уведомления пользователю.",
                Severity.HIGH,
                "PASSWORD_RESET: Нет защиты",
                dedupe,
                schemaEvidence);
        }

        // 1. Критичная операция без защиты от автоматизации
        if (!hasProtection && !hasRateLimit) {
            String automationKey = String.join("|", Optional.ofNullable(path).orElse(""), Optional.ofNullable(method).orElse(""), "No automation protection");
            if (dedupe.add(automationKey)) {
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
                
                if (hasDeviceFingerprint) {
                    severity = downgradeSeverity(severity);
                }
                if (hasBehaviorAnalytics) {
                    severity = downgradeSeverity(severity);
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
                if (hasDeviceFingerprint || hasBehaviorAnalytics) {
                    confidence = Math.max(0, confidence - 10);
                }
                
                int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(
                    tempVuln, confidence);
                
                addBusinessFlowVulnerability(vulnerabilities, typeDedup, Vulnerability.builder()
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
                    .evidence(combineEvidence("Smart risk score: " + riskScore, schemaEvidence))
                    .build());
            }
        }
        
        // 2. Операции с деньгами без дополнительной верификации
        if (!isCatalogFlow &&
            isMoneyOperation(path, operation) && !"GET".equalsIgnoreCase(method) && !hasTwoFactorAuth(operation, openAPI)) {
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
            
            if (dedupe.add("money|" + path + "|" + method)) {
                addBusinessFlowVulnerability(vulnerabilities, typeDedup, Vulnerability.builder()
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
                    .evidence(combineEvidence("Платеж/перевод без 2FA", schemaEvidence))
                    .build());
            }
        }
        
        // 3. Голосование/рейтинги без защиты
        if (isVotingOperation(path, operation) && !hasProtection) {
            if (dedupe.add("voting|" + path + "|" + method)) {
                addBusinessFlowVulnerability(vulnerabilities, typeDedup, Vulnerability.builder()
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
                .evidence(combineEvidence("Голосование без rate limit", schemaEvidence))
                .build());
            }
        }
        
        return vulnerabilities;
    }
    
    private boolean isSensitiveBusinessOperation(String path, Operation operation) {
        String text = path.toLowerCase() + " " +
                     (operation.getSummary() != null ? operation.getSummary().toLowerCase() : "") + " " +
                     (operation.getDescription() != null ? operation.getDescription().toLowerCase() : "");
        
        // Используем конфиг вместо хардкода!
        if (sensitiveOperations.stream().anyMatch(text::contains)) {
            return true;
        }
        return isMarketplaceOperation(text) || isMarketplaceRefundOperation(text) ||
            isMarketplacePayoutOperation(text) || isMerchantOnboardingOperation(text) ||
            isGovernmentServiceOperation(text) || isTelecomOperation(text) || isTelecomCriticalOperation(text) ||
            isConnectedCarOperation(text) || isOtaOperation(text) ||
            isMoneyOperation(path, operation) || isVotingOperation(path, operation);
    }
    
    private boolean hasAutomationProtection(Operation operation, FlowSchemaSignals schemaSignals) {
        String text = (operation.getDescription() != null ? operation.getDescription() : "") +
                     (operation.getSummary() != null ? operation.getSummary() : "");
        String lower = text.toLowerCase();
        
        if (schemaSignals != null && (schemaSignals.hasCaptcha || schemaSignals.hasDeviceField)) {
            return true;
        }
        // Используем конфиг вместо хардкода!
        return protectionKeywords.stream().anyMatch(lower::contains);
    }
    
    private boolean hasRateLimitProtection(Operation operation) {
        if (operation == null) {
            return false;
        }

        if (operation.getResponses() != null) {
            if (operation.getResponses().get("429") != null) {
                return true;
            }
            boolean hasHeaders = operation.getResponses().values().stream()
                .filter(response -> response != null && response.getHeaders() != null)
                .anyMatch(response -> response.getHeaders().keySet().stream()
                    .map(String::toLowerCase)
                    .anyMatch(header -> header.startsWith("x-ratelimit") || header.equals("retry-after")));
            if (hasHeaders) {
                return true;
            }
        }

        String text = ((operation.getDescription() != null ? operation.getDescription() : "") +
            (operation.getSummary() != null ? operation.getSummary() : "")).toLowerCase(Locale.ROOT);
        return text.contains("rate limit") || text.contains("throttle") || text.contains("quota") || text.contains("burst");
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
    
    private boolean hasTwoFactorAuth(Operation operation, OpenAPI openAPI) {
        if (operation == null) {
            return false;
        }

        String combined = buildCombinedText(null, operation);
        if (TWO_FACTOR_TEXT_KEYWORDS.stream().anyMatch(combined::contains)) {
            return true;
        }

        if (operation.getParameters() != null) {
            for (Parameter parameter : operation.getParameters()) {
                if (parameter == null) {
                    continue;
                }
                String name = Optional.ofNullable(parameter.getName()).orElse("").toLowerCase(Locale.ROOT);
                String description = Optional.ofNullable(parameter.getDescription()).orElse("").toLowerCase(Locale.ROOT);
                if (hasTwoFactorKeyword(name) || hasTwoFactorKeyword(description)) {
                    return true;
                }
            }
        }

        if (operation.getRequestBody() != null) {
            Content content = operation.getRequestBody().getContent();
            if (content != null && !content.isEmpty()) {
                Set<String> propertyNames = new HashSet<>();
                content.values().forEach(mediaType -> {
                    Schema<?> schema = mediaType != null ? mediaType.getSchema() : null;
                    collectSchemaPropertyNames(schema, openAPI, new HashSet<>(), propertyNames);
                });
                if (propertyNames.stream().anyMatch(this::hasTwoFactorKeyword)) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean hasTwoFactorKeyword(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        return TWO_FACTOR_PARAM_KEYWORDS.stream().anyMatch(lower::contains);
    }

    private void addBusinessFlowFinding(List<Vulnerability> vulnerabilities,
                                         String path,
                                         String method,
                                         Operation operation,
                                         int riskScore,
                                         Severity baseSeverity,
                                         String title,
                                         String description,
                                         String recommendation,
                                         Severity defaultSeverity,
                                         String impact,
                                         Set<String> dedupe,
                                         List<String> schemaEvidence) {
        String dedupeKey = String.join("|", Optional.ofNullable(path).orElse(""), Optional.ofNullable(method).orElse(""), title);
        if (!dedupe.add(dedupeKey)) {
            return;
        }
        Severity severity = baseSeverity.compareTo(defaultSeverity) < 0 ? defaultSeverity : baseSeverity;
        Vulnerability temp = Vulnerability.builder()
            .type(VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW)
            .severity(severity)
            .riskScore(riskScore)
            .build();
        int confidence = com.vtb.scanner.heuristics.ConfidenceCalculator.calculateConfidence(temp, operation, false, true);
        int priority = com.vtb.scanner.heuristics.ConfidenceCalculator.calculatePriority(temp, confidence);
        vulnerabilities.add(Vulnerability.builder()
            .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW, path, method, null, title))
            .type(VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW)
            .severity(severity)
            .riskScore(riskScore)
            .title(title)
            .description(description)
            .endpoint(path)
            .method(method)
            .recommendation(recommendation)
            .owaspCategory("API6:2023 - Unrestricted Access to Sensitive Business Flows")
            .confidence(confidence)
            .priority(priority)
            .impactLevel(impact)
            .evidence(combineEvidence(String.format("Risk Score: %d | Confidence: %d%%", riskScore, confidence), schemaEvidence))
            .build());
    }
    
    private void addBusinessFlowFinding(List<Vulnerability> vulnerabilities,
                                        String path,
                                        String method,
                                        Operation operation,
                                        int riskScore,
                                        Severity baseSeverity,
                                        String title,
                                        String description,
                                        String recommendation,
                                        Severity defaultSeverity,
                                        String impact,
                                        Set<String> dedupe) {
        addBusinessFlowFinding(vulnerabilities, path, method, operation, riskScore, baseSeverity, title, description,
            recommendation, defaultSeverity, impact, dedupe, Collections.emptyList());
    }

    private void collectSchemaPropertyNames(Schema<?> schema, OpenAPI openAPI,
                                            Set<String> visitedRefs,
                                            Set<String> names) {
        if (schema == null) {
            return;
        }

        if (schema.get$ref() != null) {
            String ref = schema.get$ref();
            if (!visitedRefs.add(ref)) {
                return;
            }
            Schema<?> resolved = resolveSchemaRef(schema, openAPI);
            if (resolved == null || resolved == schema) {
                return;
            }
            collectSchemaPropertyNames(resolved, openAPI, visitedRefs, names);
            return;
        }

        if (schema.getProperties() != null) {
            schema.getProperties().forEach((propName, propValue) -> {
                if (propName != null) {
                    names.add(propName.toLowerCase(Locale.ROOT));
                }
                Schema<?> propSchema = toSchema(propValue);
                if (propSchema != null) {
                    collectSchemaPropertyNames(propSchema, openAPI, visitedRefs, names);
                }
            });
        }

        if (schema.getAllOf() != null) {
            schema.getAllOf().forEach(child -> collectSchemaPropertyNames(child, openAPI, visitedRefs, names));
        }
        if (schema.getOneOf() != null) {
            schema.getOneOf().forEach(child -> collectSchemaPropertyNames(child, openAPI, visitedRefs, names));
        }
        if (schema.getAnyOf() != null) {
            schema.getAnyOf().forEach(child -> collectSchemaPropertyNames(child, openAPI, visitedRefs, names));
        }

        if (schema.getItems() != null) {
            collectSchemaPropertyNames(schema.getItems(), openAPI, visitedRefs, names);
        }
    }

    private Schema<?> resolveSchemaRef(Schema<?> schema, OpenAPI openAPI) {
        if (schema == null || openAPI == null || schema.get$ref() == null) {
            return schema;
        }
        String ref = schema.get$ref();
        if (ref.startsWith("#/components/schemas/") && openAPI.getComponents() != null &&
            openAPI.getComponents().getSchemas() != null) {
            String name = ref.substring("#/components/schemas/".length());
            Schema<?> resolved = openAPI.getComponents().getSchemas().get(name);
            if (resolved != null) {
                return resolved;
            }
        }
        return schema;
    }

    private Schema<?> toSchema(Object potentialSchema) {
        if (potentialSchema instanceof Schema<?>) {
            return (Schema<?>) potentialSchema;
        }
        return null;
    }

    private Severity downgradeSeverity(Severity severity) {
        if (severity == null) {
            return Severity.INFO;
        }
        return switch (severity) {
            case CRITICAL -> Severity.HIGH;
            case HIGH -> Severity.MEDIUM;
            case MEDIUM -> Severity.LOW;
            case LOW, INFO -> Severity.INFO;
        };
    }

    private boolean hasDeviceFingerprint(Operation operation) {
        String text = buildCombinedText(null, operation);
        return DEVICE_PROTECTION_KEYWORDS.stream().anyMatch(text::contains);
    }

    private boolean hasBehaviorAnalytics(Operation operation) {
        String text = buildCombinedText(null, operation);
        return BEHAVIOR_ANALYTICS_KEYWORDS.stream().anyMatch(text::contains);
    }

    private boolean hasSimBindingEvidence(Operation operation) {
        String text = buildCombinedText(null, operation);
        if (SIM_BINDING_KEYWORDS.stream().anyMatch(text::contains)) {
            return true;
        }
        if (operation != null && operation.getParameters() != null) {
            for (Parameter parameter : operation.getParameters()) {
                if (parameter == null) {
                    continue;
                }
                String name = Optional.ofNullable(parameter.getName()).orElse("").toLowerCase(Locale.ROOT);
                String description = Optional.ofNullable(parameter.getDescription()).orElse("").toLowerCase(Locale.ROOT);
                if (SIM_BINDING_KEYWORDS.stream().anyMatch(name::contains) ||
                    SIM_BINDING_KEYWORDS.stream().anyMatch(description::contains)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean hasOtaIntegrityEvidence(Operation operation) {
        String text = buildCombinedText(null, operation);
        if (OTA_PROTECTION_KEYWORDS.stream().anyMatch(text::contains)) {
            return true;
        }
        if (operation != null && operation.getRequestBody() != null) {
            String desc = Optional.ofNullable(operation.getRequestBody().getDescription()).orElse("").toLowerCase(Locale.ROOT);
            if (OTA_PROTECTION_KEYWORDS.stream().anyMatch(desc::contains)) {
                return true;
            }
        }
        return false;
    }

    private String buildCombinedText(String path, Operation operation) {
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

    private boolean isMarketplaceOperation(String text) {
        return MARKETPLACE_KEYWORDS.stream().anyMatch(text::contains);
    }

    private boolean isMarketplaceRefundOperation(String text) {
        return MARKETPLACE_SENSITIVE_KEYWORDS.stream().anyMatch(text::contains) &&
            (text.contains("refund") || text.contains("return") || text.contains("chargeback"));
    }

    private boolean isMarketplacePayoutOperation(String text) {
        return MARKETPLACE_SENSITIVE_KEYWORDS.stream().anyMatch(text::contains) &&
            (text.contains("payout") || text.contains("settlement") || text.contains("withdraw") || text.contains("payouts"));
    }

    private boolean isMerchantOnboardingOperation(String text) {
        return ONBOARDING_KEYWORDS.stream().anyMatch(text::contains) || text.contains("merchant onboarding") || text.contains("seller onboarding");
    }

    private boolean isGovernmentServiceOperation(String text) {
        return GOVERNMENT_KEYWORDS.stream().anyMatch(text::contains) || text.contains("gosuslugi") || text.contains("esia");
    }

    private boolean isTelecomOperation(String text) {
        return TELECOM_KEYWORDS.stream().anyMatch(text::contains);
    }

    private boolean isTelecomCriticalOperation(String text) {
        return TELECOM_CRITICAL_KEYWORDS.stream().anyMatch(text::contains);
    }

    private boolean isConnectedCarOperation(String text) {
        return CONNECTED_CAR_KEYWORDS.stream().anyMatch(text::contains);
    }

    private boolean isRemoteVehicleControlOperation(String text) {
        return CONNECTED_CAR_REMOTE_KEYWORDS.stream().anyMatch(text::contains);
    }

    private boolean isOtaOperation(String text) {
        return CONNECTED_CAR_OTA_KEYWORDS.stream().anyMatch(text::contains);
    }

    private boolean hasIdentityVerification(Operation operation) {
        String text = (operation.getDescription() != null ? operation.getDescription() : "") +
            (operation.getSummary() != null ? operation.getSummary() : "");
        String lower = text.toLowerCase(Locale.ROOT);
        return IDENTITY_CHECK_KEYWORDS.stream().anyMatch(lower::contains);
    }

    private boolean hasApprovalFlow(Operation operation) {
        String text = (operation.getDescription() != null ? operation.getDescription() : "") +
            (operation.getSummary() != null ? operation.getSummary() : "");
        String lower = text.toLowerCase(Locale.ROOT);
        return APPROVAL_KEYWORDS.stream().anyMatch(lower::contains);
    }

    private boolean hasFraudMonitoring(Operation operation) {
        String text = (operation.getDescription() != null ? operation.getDescription() : "") +
            (operation.getSummary() != null ? operation.getSummary() : "");
        String lower = text.toLowerCase(Locale.ROOT);
        return FRAUD_CONTROL_KEYWORDS.stream().anyMatch(lower::contains);
    }

    private boolean hasSessionHardening(Operation operation) {
        if (operation == null) {
            return false;
        }
        StringBuilder sb = new StringBuilder();
        if (operation.getDescription() != null) sb.append(operation.getDescription().toLowerCase(Locale.ROOT)).append(' ');
        if (operation.getSummary() != null) sb.append(operation.getSummary().toLowerCase(Locale.ROOT));
        String lower = sb.toString();
        return SESSION_HARDENING_KEYWORDS.stream().anyMatch(lower::contains);
    }

    private boolean isSessionOperation(String text, String method) {
        if (text == null) {
            return false;
        }
        if (SESSION_OPERATION_KEYWORDS.stream().noneMatch(text::contains)) {
            return false;
        }
        if (method != null && method.equalsIgnoreCase("GET")) {
            return text.contains("logout") || text.contains("session status");
        }
        return true;
    }

    private int applyRiskWeights(int baseScore,
                                  Operation operation,
                                  ContextAnalyzer.APIContext apiContext,
                                  boolean isMarketplaceFlow,
                                  boolean isGovernmentService,
                                  boolean hasConsentEvidence) {
        ScannerConfig.RiskWeights weights = config != null ? config.getRiskWeights() : null;
        if (weights == null) {
            return baseScore;
        }
        double adjusted = baseScore;
        Map<String, Double> multipliers = weights.getContextMultipliers();
        if (apiContext != null && multipliers != null && !multipliers.isEmpty()) {
            String key = apiContext.name().toLowerCase(Locale.ROOT);
            Double multiplier = multipliers.get(key);
            if (multiplier != null && multiplier > 0) {
                adjusted = adjusted * multiplier;
            }
        }
        boolean highContext = apiContext == ContextAnalyzer.APIContext.BANKING ||
            apiContext == ContextAnalyzer.APIContext.GOVERNMENT ||
            apiContext == ContextAnalyzer.APIContext.HEALTHCARE;
        if (featureToggles != null) {
            if (featureToggles.marketplaceEnabled() && isMarketplaceFlow) {
                if (weights.getMarketplaceFlow() != null) {
                    adjusted += weights.getMarketplaceFlow();
                }
                if (highContext && weights.getMarketplaceFlowHighContext() != null) {
                    adjusted += weights.getMarketplaceFlowHighContext();
                }
            }
            if (featureToggles.governmentEnabled() && isGovernmentService && weights.getGovernmentFlow() != null) {
                adjusted += weights.getGovernmentFlow();
            }
        }
        if (hasConsentEvidence) {
            if (weights.getConsentPresent() != null) {
                adjusted += weights.getConsentPresent();
            }
        } else {
            if (weights.getConsentMissing() != null) {
                adjusted += weights.getConsentMissing();
            }
            if (highContext && weights.getConsentMissingHighContext() != null) {
                adjusted += weights.getConsentMissingHighContext();
            }
        }
        return (int) Math.max(0, Math.round(adjusted));
    }

    private void addBusinessFlowVulnerability(List<Vulnerability> list,
                                              Set<String> typeDedup,
                                              Vulnerability vulnerability) {
        if (vulnerability == null) {
            return;
        }
        if (vulnerability.getType() != VulnerabilityType.UNRESTRICTED_BUSINESS_FLOW) {
            list.add(vulnerability);
            return;
        }
        String endpointKey = vulnerability.getEndpoint() != null ? vulnerability.getEndpoint() : "N/A";
        String methodKey = vulnerability.getMethod() != null ? vulnerability.getMethod() : "N/A";
        String key = endpointKey + "|" + methodKey + "|" + vulnerability.getType();
        if (typeDedup.add(key)) {
            list.add(vulnerability);
        } else {
            log.debug("Skipping duplicate business flow finding for {} {}", methodKey, endpointKey);
        }
    }

    private String combineEvidence(String baseEvidence, List<String> schemaEvidence) {
        if (schemaEvidence == null || schemaEvidence.isEmpty()) {
            return baseEvidence;
        }
        String schemaPart = String.join("; ", schemaEvidence);
        if (baseEvidence == null || baseEvidence.isBlank()) {
            return schemaPart;
        }
        return baseEvidence + " | " + schemaPart;
    }

    private boolean containsKeyword(String text, Set<String> keywords) {
        if (text == null || text.isBlank() || keywords == null || keywords.isEmpty()) {
            return false;
        }
        String lower = text.toLowerCase(Locale.ROOT);
        for (String keyword : keywords) {
            if (lower.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    private boolean isCaptchaIndicator(String lowerName) {
        if (lowerName == null) {
            return false;
        }
        for (String keyword : CAPTCHA_FIELD_KEYWORDS) {
            if (lowerName.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    private boolean isDeviceIndicator(String lowerName) {
        if (lowerName == null) {
            return false;
        }
        for (String keyword : DEVICE_FIELD_KEYWORDS) {
            if (lowerName.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    private static final class FlowSchemaSignals {
        final boolean hasCaptcha;
        final boolean hasDeviceField;
        final List<String> evidenceNotes;
        final int guardMitigationScore;
        final SchemaConstraints.GuardStrength strongestGuard;

        private FlowSchemaSignals(boolean hasCaptcha,
                                  boolean hasDeviceField,
                                  List<String> evidenceNotes,
                                  int guardMitigationScore,
                                  SchemaConstraints.GuardStrength strongestGuard) {
            this.hasCaptcha = hasCaptcha;
            this.hasDeviceField = hasDeviceField;
            this.evidenceNotes = evidenceNotes;
            this.guardMitigationScore = guardMitigationScore;
            this.strongestGuard = strongestGuard;
        }

        static FlowSchemaSignals empty() {
            return new FlowSchemaSignals(false, false, Collections.emptyList(), 0, SchemaConstraints.GuardStrength.NONE);
        }

        List<String> evidenceNotes() {
            return evidenceNotes;
        }

        int guardMitigationScore() {
            return guardMitigationScore;
        }

        SchemaConstraints.GuardStrength strongestGuard() {
            return strongestGuard;
        }

        static Builder builder() {
            return new Builder();
        }

        static final class Builder {
            private boolean hasCaptcha;
            private boolean hasDeviceField;
            private final Set<String> evidence = new LinkedHashSet<>();
            private int guardMitigationScore;
            private SchemaConstraints.GuardStrength strongestGuard = SchemaConstraints.GuardStrength.NONE;

            void markCaptcha(String location, SchemaConstraints constraints) {
                hasCaptcha = true;
                addEvidence(location, constraints);
            }

            void markDevice(String location, SchemaConstraints constraints) {
                hasDeviceField = true;
                addEvidence(location, constraints);
            }

            void registerGuard(SchemaConstraints constraints) {
                if (constraints == null) {
                    return;
                }
                SchemaConstraints.GuardStrength guardStrength = constraints.getGuardStrength();
                if (guardStrength == null) {
                    return;
                }
                strongestGuard = pickStronger(strongestGuard, guardStrength);
                guardMitigationScore = Math.min(guardMitigationScore + guardScore(guardStrength), 40);
            }

            private SchemaConstraints.GuardStrength pickStronger(SchemaConstraints.GuardStrength current,
                                                                 SchemaConstraints.GuardStrength candidate) {
                if (candidate == null) {
                    return current;
                }
                if (current == null || candidate.ordinal() > current.ordinal()) {
                    return candidate;
                }
                return current;
            }

            private int guardScore(SchemaConstraints.GuardStrength strength) {
                return switch (strength) {
                    case NOT_USER_CONTROLLED -> 18;
                    case STRONG -> 12;
                    case MODERATE -> 6;
                    case WEAK -> 2;
                    case NONE -> 0;
                };
            }

            void addEvidence(String location, SchemaConstraints constraints) {
                registerGuard(constraints);
                String formatted = location != null ? (constraints != null ? constraints.buildEvidenceNote() : null) : null;
                String note = location;
                if (formatted != null && !formatted.isBlank()) {
                    note = location + " → " + formatted;
                }
                if (note != null && !note.isBlank()) {
                    evidence.add(note);
                }
            }

            FlowSchemaSignals build() {
                return new FlowSchemaSignals(
                    hasCaptcha,
                    hasDeviceField,
                    evidence.isEmpty() ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(evidence)),
                    guardMitigationScore,
                    strongestGuard
                );
            }
        }
    }

    private static final Set<String> CAPTCHA_FIELD_KEYWORDS = Set.of(
        "captcha", "recaptcha", "hcaptcha", "turnstile", "cf-turnstile", "challenge", "botcheck"
    );
    private static final Set<String> CAPTCHA_TEXT_KEYWORDS = Set.of(
        "captcha", "bot protection", "anti-bot", "challenge", "turnstile", "human verification"
    );
    private static final Set<String> DEVICE_FIELD_KEYWORDS = Set.of(
        "device", "fingerprint", "trusteddevice", "trusted-device", "psu-device", "psudevice",
        "deviceid", "device_id", "device-token", "devicetoken", "hardwareid", "hardware-id",
        "imei", "imsi", "iccid", "browserfingerprint", "authdevice"
    );
    private static final Set<String> DEVICE_TEXT_KEYWORDS = Set.of(
        "device binding", "device fingerprint", "trusted device", "hardware id", "imei", "imsi",
        "iccid", "psu-device", "psu device", "fingerprint", "device token", "secure device"
    );

    private static final Set<String> MARKETPLACE_KEYWORDS = Set.of(
        "order", "checkout", "cart", "basket", "purchase", "shipment", "fulfillment",
        "seller", "merchant", "vendor", "listing", "inventory", "reservation",
        "маркетплейс", "заказ", "корзина", "покупка", "доставка", "продавец", "витрина", "товар",
        "маркет", "продажа", "marketplace", "sku"
    );
    private static final Set<String> MARKETPLACE_SENSITIVE_KEYWORDS = Set.of(
        "refund", "return", "chargeback", "payout", "settlement", "commission", "withdraw",
        "возврат", "выплата", "агентское", "поступление", "перечисление", "выкуп", "комиссия"
    );
    private static final Set<String> GOVERNMENT_KEYWORDS = Set.of(
        "permit", "license", "passport", "tax", "registry", "application",
        "court", "fine", "ticket", "social", "benefit",
        "gosuslugi", "esia", "smev", "pgu", "nalog", "rosreestr", "gibdd", "fns",
        "мфц", "свидетельство", "справка", "услуга", "соцподдержка", "льгота", "выписка", "реестр"
    );
    private static final Set<String> ONBOARDING_KEYWORDS = Set.of(
        "onboarding", "kyc", "kyb", "verification", "document", "compliance", "aml",
        "application", "enrollment", "approval",
        "онбординг", "идентификация", "подключение", "регистрация продавца", "подписание договора",
        "досье", "анкета", "профилирование"
    );
    private static final Set<String> IDENTITY_CHECK_KEYWORDS = Set.of(
        "id verification", "identity", "passport", "document upload", "ocr", "kyc", "photo", "selfie",
        "esia", "есиа", "биометрия", "единая биометрическая система", "скан паспорта", "удостоверение личности",
        "ebs", "единая биометрия", "единобиом", "биометрическое подтверждение"
    );
    private static final Set<String> APPROVAL_KEYWORDS = Set.of(
        "manual review", "approval", "moderation", "verification team", "compliance review", "manager",
        "workflow", "two step", "queue",
        "ручная проверка", "согласование", "одобрение", "модерация", "комиссия", "двухэтапное согласование",
        "комитет", "second pair of eyes", "двухконтроль", "ручной контроль"
    );
    private static final Set<String> FRAUD_CONTROL_KEYWORDS = Set.of(
        "fraud", "anti-fraud", "risk score", "velocity", "abuse", "monitoring", "anomaly",
        "антифрод", "анти-фрод", "скоринг", "мошенничество", "поведенческий анализ", "скоринг риска", "aml",
        "anti fraud", "risk engine", "fraud monitor", "антифродовый контроль", "скоринг транзакций"
    );
    private static final Set<String> TELECOM_KEYWORDS = Set.of(
        "msisdn", "sim", "e-sim", "esim", "imsi", "iccid", "vsim", "subscriber",
        "topup", "recharge", "balance", "plan change", "tariff", "roaming", "call forwarding", "voice mail",
        "перенос номера", "смена тарифа", "пополнение", "расход трафика", "услуга связи", "сотовый оператор", "биллинг", "переадресация"
    );
    private static final Set<String> TELECOM_CRITICAL_KEYWORDS = Set.of(
        "sim swap", "sim-swap", "sim change", "esim activation", "roaming activation", "transfer msisdn",
        "sim replacement", "msisdn transfer", "tariff upgrade", "telecom consent",
        "запрос puk", "смена sim", "активация e-sim", "активация роуминга", "перевыпуск sim", "блокировка sim"
    );
    private static final Set<String> CONNECTED_CAR_KEYWORDS = Set.of(
        "telematics", "vehicle", "car", "vin", "connected car", "lada connect", "remote car", "door lock",
        "engine start", "climate control", "charging", "battery status", "vehicle status", "smart car",
        "удалённый запуск", "удаленное управление", "телематика", "открыть двери", "подогрев", "запуск двигателя", "автомобиль", "remote cabin"
    );
    private static final Set<String> CONNECTED_CAR_REMOTE_KEYWORDS = Set.of(
        "remote start", "remote unlock", "remote lock", "remote engine", "remote climate",
        "удаленный запуск", "дистанционный запуск", "удаленное открытие", "удаленное закрытие",
        "remote horn", "remote lights", "remote alarm", "engine stop", "door unlock", "remote immobilizer"
    );
    private static final Set<String> CONNECTED_CAR_OTA_KEYWORDS = Set.of(
        "ota", "over-the-air", "firmware", "software update", "ecu update", "ota update",
        "обновление прошивки", "обновление по воздуху", "обновление ecu", "прошивка", "обновление software", "обновление блока"
    );
    private static final Set<String> SIM_BINDING_KEYWORDS = Set.of(
        "sim binding", "sim-lock", "trusted sim", "device binding", "psu-device", "x-psu-device", "msisdn token", "sim token",
        "imsi", "icc", "sim-id", "trusted device", "sim fingerprint", "secure sim", "device fingerprint", "sim verification"
    );
    private static final Set<String> OTA_PROTECTION_KEYWORDS = Set.of(
        "signature", "signed", "hash", "checksum", "secure boot", "verity", "integrity", "pkcs7",
        "подпись", "цифровая подпись", "контроль целостности", "хэш", "secure firmware", "signature verification", "trusted boot"
    );
    private static final Set<String> CONSENT_EXPECTATION_KEYWORDS = Set.of(
        "consent", "permission", "scopes", "agreements", "privacy", "data sharing",
        "согласие", "соглашение", "оферта", "esia", "esid", "роспотребнадзор", "согласование", "мссу",
        "msisdn", "trusted device"
    );
    private static final Set<String> SESSION_OPERATION_KEYWORDS = Set.of(
        "session", "token", "logout", "signout", "revoke", "refresh", "jwt", "cookie",
        "сессия", "выход", "обновить токен", "sessionid", "auth-token", "access-token",
        "msisdn"
    );
    private static final Set<String> SESSION_HARDENING_KEYWORDS = Set.of(
        "invalidate", "expire", "expiration", "timeout", "rotation", "regenerate",
        "one-time", "single use", "limit", "ttl", "lifetime", "revoke",
        "просрочка", "отозвать", "истечение", "ограничение времени", "лимит сессий",
        "прекращение", "истекает", "длительность", "session ttl"
    );
    private static final Set<String> TWO_FACTOR_TEXT_KEYWORDS = Set.of(
        "2fa", "mfa", "otp", "two-factor", "two factor", "one-time password", "challenge code",
        "authenticator app", "hardware token", "sms code", "confirm code",
        "смс-код", "смс код", "push-уведомление", "esid", "esia", "одноразовый пароль", "код подтверждения",
        "3ds", "miraccept", "visa secure", "mastercard identity check", "push-код",
        "voice biometric", "ussd"
    );
    private static final Set<String> TWO_FACTOR_PARAM_KEYWORDS = Set.of(
        "otp", "mfa", "2fa", "one_time_code", "verification_code", "auth_code", "challenge", "totp", "passcode",
        "sms_code", "esa_code", "esid", "push_code", "3ds_token", "mir_code", "securecode", "otp_sms",
        "msisdn"
    );
    private static final Set<String> DEVICE_PROTECTION_KEYWORDS = Set.of(
        "device fingerprint", "device binding", "trusted device", "device id", "device fingerprinting",
        "biometric", "behavioural biometric",
        "фингерпринт устройства", "привязка устройства", "доверенное устройство", "биометрия", "единобиом", "ebs",
        "device token", "psu-device", "id устройства", "fingerprint",
        "msisdn", "trusted sim", "device serial", "vin", "telematics unit"
    );
    private static final Set<String> BEHAVIOR_ANALYTICS_KEYWORDS = Set.of(
        "behavior analytics", "behaviour analytics", "risk score", "risk scoring", "velocity check",
        "anomaly detection", "fraud score", "behaviour monitoring",
        "поведенческий анализ", "антифрод мониторинг", "скоринг риска", "анализ транзакций",
        "risk-профиль", "поведенческая биометрия",
        "telematics analytics", "device diagnostics"
    );
    private static final Set<String> HIGH_VALUE_OPERATION_KEYWORDS = Set.of(
        "treasury", "bulk payment", "mass payment", "payroll", "salary payout", "swift",
        "rtgs", "high value", "wholesale payment", "treasury transfer", "cash concentration",
        "sbbol", "корпоративный платеж", "зарплатный проект", "казначейство", "крупный платеж", "межбанк", "система быстрых платежей",
        "спб", "sbp", "высокая сумма", "межбанковский перевод", "swift mt"
    );
    private static final Set<String> BULK_OPERATION_KEYWORDS = Set.of(
        "batch", "bulk", "mass", "multi transfer", "file upload payment", "aggregate transfer", "group transfer",
        "массовый", "пакет", "реестр", "ведомость", "загрузка файла", "групповой перевод",
        "multitransfer", "единый реестр", "зарплатная ведомость"
    );
    private static final Set<String> LOAN_OPERATION_KEYWORDS = Set.of(
        "loan", "credit", "mortgage", "microloan", "installment", "disbursement", "issuance", "lending", "credit line",
        "кредит", "ипотека", "рассрочка", "займ", "овердрафт", "кредитная линия", "refinancing",
        "refinance", "переуступка", "лизинг", "обеспечение", "страховая премия"
    );

    @SuppressWarnings("unchecked")
    private Map<String, Schema<?>> castSchemaMap(Map<String, Schema> properties) {
        if (properties == null) {
            return null;
        }
        return (Map<String, Schema<?>>) (Map<?, ?>) properties;
    }
}

