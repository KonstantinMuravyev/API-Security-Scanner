package com.vtb.scanner.models;

/**
 * Типы нарушений контракта API
 */
public enum ViolationType {
    MISSING_FIELD("Отсутствует обязательное поле"),
    WRONG_TYPE("Неверный тип данных"),
    UNEXPECTED_FIELD("Неожиданное поле в ответе"),
    MISSING_ENDPOINT("Эндпоинт не описан в спецификации"),
    WRONG_STATUS_CODE("Неверный код ответа"),
    SCHEMA_MISMATCH("Несоответствие схеме"),
    MISSING_HEADER("Отсутствует обязательный заголовок"),
    INVALID_FORMAT("Неверный формат данных");
    
    private final String description;
    
    ViolationType(String description) {
        this.description = description;
    }
    
    public String getDescription() {
        return description;
    }
}

