package com.vtb.scanner.models;

/**
 * Уровни критичности уязвимостей
 */
public enum Severity {
    CRITICAL("Критический", 5),
    HIGH("Высокий", 4),
    MEDIUM("Средний", 3),
    LOW("Низкий", 2),
    INFO("Информационный", 1);
    
    private final String russianName;
    private final int priority;
    
    Severity(String russianName, int priority) {
        this.russianName = russianName;
        this.priority = priority;
    }
    
    public String getRussianName() {
        return russianName;
    }
    
    public int getPriority() {
        return priority;
    }
}

