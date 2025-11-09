package com.vtb.scanner.semantic;

import io.swagger.v3.oas.models.Operation;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;

/**
 * Классификатор операций API
 * Определяет семантический тип операции
 */
@Slf4j
public class OperationClassifier {
    
    /**
     * Тип операции
     */
    public enum OperationType {
        READ("Чтение"),
        CREATE("Создание"),
        UPDATE("Обновление"),
        DELETE("Удаление"),
        LOGIN("Вход"),
        REGISTER("Регистрация"),
        PAYMENT("Платеж"),
        TRANSFER_MONEY("Перевод денег"),
        WITHDRAWAL("Снятие средств"),
        ADMIN_ACTION("Административное действие"),
        USER_MANAGEMENT("Управление пользователями"),
        ROLE_MANAGEMENT("Управление ролями"),
        SEARCH("Поиск"),
        QUERY("Запрос"),
        UNKNOWN("Неизвестно");
        
        private final String description;
        
        OperationType(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * Классифицировать операцию
     */
    public static OperationType classify(String path, String method, Operation operation) {
        if (path == null || method == null) {
            return OperationType.UNKNOWN;
        }
        
        String pathLower = path.toLowerCase();
        String methodUpper = method.toUpperCase();
        String description = "";
        String summary = "";
        
        if (operation != null) {
            description = operation.getDescription() != null ? 
                operation.getDescription().toLowerCase() : "";
            summary = operation.getSummary() != null ? 
                operation.getSummary().toLowerCase() : "";
        }
        
        String combined = (pathLower + " " + description + " " + summary).toLowerCase();
        
        // Метод
        if ("GET".equals(methodUpper)) {
            if (pathLower.contains("login") || combined.contains("login") || 
                combined.contains("signin") || combined.contains("authenticate")) {
                return OperationType.LOGIN;
            }
            
            if (pathLower.contains("search") || combined.contains("search") ||
                pathLower.contains("find") || combined.contains("find")) {
                return OperationType.SEARCH;
            }
            
            return OperationType.READ;
        }
        
        if ("POST".equals(methodUpper)) {
            if (pathLower.contains("register") || combined.contains("register") ||
                pathLower.contains("signup") || combined.contains("signup") ||
                combined.contains("create account")) {
                return OperationType.REGISTER;
            }
            
            if (pathLower.contains("login") || combined.contains("login") ||
                combined.contains("signin")) {
                return OperationType.LOGIN;
            }
            
            if (pathLower.contains("payment") || combined.contains("payment") ||
                pathLower.contains("pay") || combined.contains("pay") ||
                combined.contains("checkout")) {
                return OperationType.PAYMENT;
            }
            
            if (pathLower.contains("transfer") || combined.contains("transfer") ||
                combined.contains("перевод")) {
                return OperationType.TRANSFER_MONEY;
            }
            
            if (pathLower.contains("withdraw") || combined.contains("withdraw") ||
                combined.contains("снятие")) {
                return OperationType.WITHDRAWAL;
            }
            
            if (pathLower.contains("admin") || combined.contains("admin")) {
                return OperationType.ADMIN_ACTION;
            }
            
            return OperationType.CREATE;
        }
        
        if ("PUT".equals(methodUpper) || "PATCH".equals(methodUpper)) {
            if (pathLower.contains("role") || combined.contains("role") ||
                pathLower.contains("permission") || combined.contains("permission")) {
                return OperationType.ROLE_MANAGEMENT;
            }
            
            if (pathLower.contains("user") && pathLower.contains("admin")) {
                return OperationType.USER_MANAGEMENT;
            }
            
            if (pathLower.contains("admin") || combined.contains("admin")) {
                return OperationType.ADMIN_ACTION;
            }
            
            return OperationType.UPDATE;
        }
        
        if ("DELETE".equals(methodUpper)) {
            if (pathLower.contains("admin") || combined.contains("admin")) {
                return OperationType.ADMIN_ACTION;
            }
            
            return OperationType.DELETE;
        }
        
        return OperationType.UNKNOWN;
    }
    
    /**
     * Получить требования безопасности для типа операции
     */
    public static List<String> getRequirements(OperationType type) {
        List<String> requirements = new ArrayList<>();
        
        switch (type) {
            case LOGIN, REGISTER -> {
                requirements.add("ОБЯЗАТЕЛЬНА аутентификация");
                requirements.add("Рекомендуется rate limiting");
                requirements.add("Рекомендуется CAPTCHA");
            }
            case PAYMENT, TRANSFER_MONEY, WITHDRAWAL -> {
                requirements.add("ОБЯЗАТЕЛЬНА аутентификация");
                requirements.add("ОБЯЗАТЕЛЬНА 2FA");
                requirements.add("ОБЯЗАТЕЛЬЕН rate limiting");
                requirements.add("Рекомендуется transaction signing");
            }
            case ADMIN_ACTION, USER_MANAGEMENT, ROLE_MANAGEMENT -> {
                requirements.add("ОБЯЗАТЕЛЬНА аутентификация");
                requirements.add("ОБЯЗАТЕЛЬНА авторизация (role-based)");
            }
            case DELETE -> {
                requirements.add("ОБЯЗАТЕЛЬНА аутентификация");
                requirements.add("Рекомендуется подтверждение");
            }
            default -> {
                requirements.add("Рекомендуется аутентификация");
            }
        }
        
        return requirements;
    }
}

