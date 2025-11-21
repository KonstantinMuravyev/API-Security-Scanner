package com.vtb.scanner.semantic;

import com.vtb.scanner.models.Severity;
import io.swagger.v3.oas.models.OpenAPI;
import lombok.extern.slf4j.Slf4j;

/**
 * Анализатор контекста API
 * Определяет тип API (банк, медицина, госуслуги и т.д.)
 */
@Slf4j
public class ContextAnalyzer {
    
    /**
     * Тип контекста API
     */
    public enum APIContext {
        BANKING("Банковский"),
        HEALTHCARE("Медицинский"),
        GOVERNMENT("Государственный"),
        ECOMMERCE("Электронная коммерция"),
        SOCIAL("Социальные сети"),
        IOT("IoT"),
        TELECOM("Телеком"),
        AUTOMOTIVE("Connected Car / Автотелеематика"),
        GENERAL("Общий");
        
        private final String description;
        
        APIContext(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    /**
     * Определить контекст API
     */
    public static APIContext detectContext(OpenAPI openAPI) {
        if (openAPI == null) {
            return APIContext.GENERAL;
        }
        
        String title = openAPI.getInfo() != null && openAPI.getInfo().getTitle() != null ?
            openAPI.getInfo().getTitle().toLowerCase() : "";
        String description = openAPI.getInfo() != null && openAPI.getInfo().getDescription() != null ?
            openAPI.getInfo().getDescription().toLowerCase() : "";
        
        String combined = (title + " " + description).toLowerCase();
        
        // Банковский
        if (combined.contains("bank") || combined.contains("банк") || 
            combined.contains("payment") || combined.contains("payment") ||
            combined.contains("account") || combined.contains("счет") ||
            combined.contains("transaction") || combined.contains("транзакция")) {
            return APIContext.BANKING;
        }
        
        // Медицинский
        if (combined.contains("health") || combined.contains("медицин") ||
            combined.contains("patient") || combined.contains("пациент") ||
            combined.contains("diagnosis") || combined.contains("диагноз") ||
            combined.contains("medical") || combined.contains("медицин")) {
            return APIContext.HEALTHCARE;
        }
        
        // Государственный
        if (combined.contains("government") || combined.contains("государств") ||
            combined.contains("gosuslugi") || combined.contains("госуслуг") ||
            combined.contains("citizen") || combined.contains("гражданин")) {
            return APIContext.GOVERNMENT;
        }
        
        // E-commerce
        if (combined.contains("shop") || combined.contains("магазин") ||
            combined.contains("store") || combined.contains("ecommerce") ||
            combined.contains("order") || combined.contains("заказ") ||
            combined.contains("product") || combined.contains("товар")) {
            return APIContext.ECOMMERCE;
        }
        
        // Социальные сети
        if (combined.contains("social") || combined.contains("социальн") ||
            combined.contains("post") || combined.contains("post") ||
            combined.contains("friend") || combined.contains("друг")) {
            return APIContext.SOCIAL;
        }
        
        // IoT
        if (combined.contains("telecom") || combined.contains("оператор") ||
            combined.contains("msisdn") || combined.contains("subscriber") ||
            combined.contains("sim") || combined.contains("sbermobile") ||
            combined.contains("mobile") || combined.contains("roaming")) {
            return APIContext.TELECOM;
        }

        if (combined.contains("vehicle") || combined.contains("авто") ||
            combined.contains("lada") || combined.contains("vin") ||
            combined.contains("telematics") || combined.contains("ota") ||
            combined.contains("ecu") || combined.contains("connected car")) {
            return APIContext.AUTOMOTIVE;
        }

        if (combined.contains("iot") || combined.contains("device") ||
            combined.contains("sensor") || combined.contains("устройств")) {
            return APIContext.IOT;
        }
        
        return APIContext.GENERAL;
    }
    
    /**
     * Получить модификатор severity для контекста
     */
    public static SeverityModifier getSeverityModifier(APIContext context) {
        return new SeverityModifier(context);
    }
    
    /**
     * Модификатор severity на основе контекста
     */
    public static class SeverityModifier {
        private final APIContext context;
        
        public SeverityModifier(APIContext context) {
            this.context = context;
        }
        
        /**
         * Применить модификатор к severity
         */
        public Severity apply(Severity originalSeverity, String vulnerabilityType) {
            if (originalSeverity == null) return Severity.MEDIUM;
            
            // Для критичных контекстов повышаем severity
            if (context == APIContext.BANKING || 
                context == APIContext.HEALTHCARE || 
                context == APIContext.GOVERNMENT ||
                context == APIContext.TELECOM ||
                context == APIContext.AUTOMOTIVE) {
                
                // ГОСТ и ФЗ-152 для банков/медицины/госуслуг - критичнее
                if (vulnerabilityType != null && 
                    (vulnerabilityType.contains("GOST") || 
                     vulnerabilityType.contains("FZ152"))) {
                    
                    switch (originalSeverity) {
                        case LOW -> { return Severity.MEDIUM; }
                        case MEDIUM -> { return Severity.HIGH; }
                        case HIGH -> { return Severity.CRITICAL; }
                        default -> {}
                    }
                }
            }
            
            return originalSeverity;
        }
    }
}

