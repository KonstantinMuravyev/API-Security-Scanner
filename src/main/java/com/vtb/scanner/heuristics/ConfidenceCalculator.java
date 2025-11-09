package com.vtb.scanner.heuristics;

import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.Operation;
import lombok.extern.slf4j.Slf4j;

/**
 * Калькулятор уверенности (confidence) в обнаружении уязвимости
 * Динамический расчет на основе множества факторов
 */
@Slf4j
public class ConfidenceCalculator {
    
    /**
     * Вычислить confidence (0-100)
     * @param vuln уязвимость
     * @param operation операция (может быть null)
     * @param hasCorrelation есть ли корреляция с другими эндпоинтами
     * @param hasEvidence есть ли доказательства (risk score, паттерны и т.д.)
     * @return confidence 0-100
     */
    public static int calculateConfidence(Vulnerability vuln, Operation operation, 
                                         boolean hasCorrelation, boolean hasEvidence) {
        if (vuln == null) return 50; // Средняя уверенность по умолчанию
        
        int confidence = 50; // Базовая уверенность
        
        // Severity влияет на confidence
        switch (vuln.getSeverity()) {
            case CRITICAL -> confidence += 30;
            case HIGH -> confidence += 20;
            case MEDIUM -> confidence += 10;
            case LOW -> confidence += 5;
            default -> {}
        }
        
        // Risk score влияет
        if (vuln.getRiskScore() > 0) {
            if (vuln.getRiskScore() > 150) {
                confidence += 20;
            } else if (vuln.getRiskScore() > 100) {
                confidence += 15;
            } else if (vuln.getRiskScore() > 50) {
                confidence += 10;
            }
        }
        
        // Корреляция повышает уверенность
        if (hasCorrelation) {
            confidence += 15;
        }
        
        // Доказательства повышают уверенность
        if (hasEvidence) {
            confidence += 10;
        }
        
        // Тип уязвимости влияет
        if (vuln.getType() != null) {
            switch (vuln.getType()) {
                case BOLA -> confidence += 5; // BOLA легко обнаружить
                case SQL_INJECTION, COMMAND_INJECTION -> confidence += 10; // Явные паттерны
                case GOST_VIOLATION, FZ152_VIOLATION -> confidence += 8; // Специфичные проверки
                default -> {}
            }
        }
        
        // Если есть evidence в описании
        if (vuln.getEvidence() != null && !vuln.getEvidence().isEmpty()) {
            confidence += 5;
        }
        
        return Math.min(100, Math.max(0, confidence));
    }
    
    /**
     * Вычислить приоритет исправления (1-5, где 1 = самый высокий)
     */
    public static int calculatePriority(Vulnerability vuln, int confidence) {
        if (vuln == null) return 3;
        
        int priority = 3; // Средний приоритет
        
        // Severity влияет на приоритет
        switch (vuln.getSeverity()) {
            case CRITICAL -> priority = 1; // Критичные исправляем первыми
            case HIGH -> priority = 2;
            case MEDIUM -> priority = 3;
            case LOW -> priority = 4;
            case INFO -> priority = 5;
        }
        
        // Высокий confidence может повысить приоритет
        if (confidence >= 90 && priority > 1) {
            priority--;
        }
        
        // Низкий confidence может снизить приоритет
        if (confidence < 50 && priority < 5) {
            priority++;
        }
        
        return Math.max(1, Math.min(5, priority));
    }
    
    /**
     * Вычислить уровень влияния на бизнес
     */
    public static String calculateImpact(Vulnerability vuln) {
        if (vuln == null) return "UNKNOWN";
        
        Severity severity = vuln.getSeverity();
        VulnerabilityType type = vuln.getType();
        
        if (severity == Severity.CRITICAL) {
            if (type == VulnerabilityType.BOLA || type == VulnerabilityType.BFLA) {
                return "DATA_BREACH: Утечка данных пользователей";
            }
            if (type == VulnerabilityType.SQL_INJECTION || type == VulnerabilityType.COMMAND_INJECTION) {
                return "SYSTEM_COMPROMISE: Полный компрометация системы";
            }
            if (type == VulnerabilityType.GOST_VIOLATION || type == VulnerabilityType.FZ152_VIOLATION) {
                return "COMPLIANCE_VIOLATION: Нарушение законодательства";
            }
            return "CRITICAL: Критичное влияние на безопасность";
        }
        
        if (severity == Severity.HIGH) {
            if (type == VulnerabilityType.BROKEN_AUTHENTICATION) {
                return "AUTH_BYPASS: Обход аутентификации";
            }
            if (type == VulnerabilityType.SSRF) {
                return "NETWORK_ATTACK: Атака на внутреннюю сеть";
            }
            return "HIGH: Высокий риск для безопасности";
        }
        
        if (severity == Severity.MEDIUM) {
            return "MEDIUM: Средний риск";
        }
        
        if (severity == Severity.LOW) {
            return "LOW: Низкий риск";
        }
        
        return "INFO: Информационное сообщение";
    }
}

