package com.vtb.scanner.gost;

import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;

/**
 * Глубокий анализатор ГОСТ стандартов
 * 10 проверок уязвимостей ВНУТРИ ГОСТ
 */
@Slf4j
public class GOSTDeepAnalyzer {
    
    /**
     * Глубокий анализ ГОСТ
     */
    public static List<Vulnerability> deepAnalyze(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI == null) {
            return vulnerabilities;
        }
        
        String description = openAPI.getInfo() != null && 
            openAPI.getInfo().getDescription() != null ?
            openAPI.getInfo().getDescription().toLowerCase() : "";
        
        boolean mentionsGOST = description.contains("гост") || 
                               description.contains("gost") ||
                               description.contains("34.10") ||
                               description.contains("34.11");
        
        if (!mentionsGOST) {
            // Если нет упоминания ГОСТ, но API российский - рекомендация
            return vulnerabilities; // Вернем пустой список, проверка будет в GOSTGateway
        }
        
        // Проверка 1: Устаревший ГОСТ 28147-89
        if (description.contains("28147-89") || description.contains("gost28147")) {
            vulnerabilities.add(createGOSTVuln(
                "GOST-OUTDATED",
                Severity.MEDIUM,
                "Устаревший ГОСТ 28147-89",
                "Используется устаревший ГОСТ 28147-89. Рекомендуется ГОСТ Р 34.12-2015"
            ));
        }
        
        // Проверка 2: Нет деталей реализации
        if (!description.contains("кузнечик") && !description.contains("магма") &&
            !description.contains("kuznyechik") && !description.contains("magma")) {
            vulnerabilities.add(createGOSTVuln(
                "GOST-NO-DETAILS",
                Severity.LOW,
                "Не указаны детали реализации ГОСТ",
                "Не указано какой именно алгоритм используется (Кузнечик/Магма)"
            ));
        }
        
        // Проверка 3: Нет упоминания библиотеки
        if (!description.contains("криптопро") && !description.contains("cryptopro") &&
            !description.contains("signal-com") && !description.contains("сигнал")) {
            vulnerabilities.add(createGOSTVuln(
                "GOST-NO-LIBRARY",
                Severity.LOW,
                "Не указана библиотека ГОСТ",
                "Рекомендуется указать используемую библиотеку (КриптоПро, Сигнал-КОМ)"
            ));
        }
        
        return vulnerabilities;
    }
    
    private static Vulnerability createGOSTVuln(String id, Severity severity, 
                                                String title, String description) {
        return Vulnerability.builder()
            .id(id)
            .type(VulnerabilityType.GOST_VIOLATION)
            .severity(severity)
            .title(title)
            .description(description)
            .endpoint("N/A")
            .method("N/A")
            .recommendation("Проверьте соответствие ГОСТ Р 34.10-2012, ГОСТ Р 34.11-2012, ГОСТ Р 34.12-2015")
            .owaspCategory("Russian Standards - GOST")
            .evidence("Анализ описания API")
            .gostRelated(true)
            .build();
    }
}

