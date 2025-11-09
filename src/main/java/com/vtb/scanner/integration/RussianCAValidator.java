package com.vtb.scanner.integration;

import java.util.Arrays;
import java.util.List;

/**
 * Валидатор российских удостоверяющих центров (УЦ)
 * Проверяет что сертификат выдан аккредитованным ФСБ УЦ
 */
public class RussianCAValidator {
    
    // Аккредитованные ФСБ России удостоверяющие центры
    private static final List<String> ACCREDITED_CAS = Arrays.asList(
        // Крупные коммерческие УЦ
        "CRYPTO-PRO",
        "CryptoPro",
        "КриптоПро",
        "Крипто-Про",
        
        "Signal-COM",
        "Сигнал-КОМ",
        
        "Контур",
        "SKB Kontur",
        "СКБ Контур",
        
        "Такском",
        "TAXCOM",
        
        // Государственные УЦ
        "Казначейство России",
        "Federal Treasury",
        "Минцифры",
        "Ministry of Digital",
        
        "ФНС России",
        "Tax Service",
        
        "Росреестр",
        "Rosreestr",
        
        // Банковские УЦ
        "ЦБ РФ",
        "Central Bank",
        "Сбербанк-АСТ",
        "Sberbank",
        
        // Телеком УЦ
        "Ростелеком",
        "Rostelecom",
        "МТС",
        "MTS"
    );
    
    /**
     * Проверить является ли УЦ российским аккредитованным
     */
    public static boolean isRussianAccreditedCA(String issuer) {
        if (issuer == null || issuer.isEmpty()) {
            return false;
        }
        
        String upperIssuer = issuer.toUpperCase();
        
        return ACCREDITED_CAS.stream()
            .anyMatch(ca -> upperIssuer.contains(ca.toUpperCase()));
    }
    
    /**
     * Получить список аккредитованных УЦ
     */
    public static List<String> getAccreditedCAs() {
        return ACCREDITED_CAS;
    }
    
    /**
     * Получить рекомендацию по УЦ
     */
    public static String getRecommendation() {
        return """
            Рекомендуемые аккредитованные ФСБ России УЦ:
            
            Коммерческие:
            • ООО "КРИПТО-ПРО" (www.cryptopro.ru)
            • ООО "Сигнал-КОМ" (www.signal-com.ru)  
            • АО "ПФ "СКБ Контур" (www.kontur.ru)
            • АО "ТАКСКОМ" (www.taxcom.ru)
            
            Государственные:
            • Казначейство России (roskazna.gov.ru)
            • ФНС России (nalog.gov.ru)
            • Росреестр (rosreestr.gov.ru)
            
            Банковские:
            • ПАО Сбербанк (sberbank.ru)
            • Банк России (cbr.ru)
            
            Требования:
            • Сертификация ФСБ России
            • Поддержка ГОСТ Р 34.10-2012
            • Поддержка ГОСТ Р 34.11-2012 (Стрибог)
            """;
    }
}

