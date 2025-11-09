package com.vtb.scanner.integration;

import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.*;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Анализатор ГОСТ криптографии в TLS
 * ФОКУС: ТОЛЬКО российские стандарты!
 * 
 * Проверяем ВСЕГДА, для ЛЮБОГО API (банк или нет - всё равно!)
 */
@Slf4j
public class TLSAnalyzer {
    
    // ГОСТ cipher suites (российская криптография)
    private static final Set<String> GOST_CIPHER_SUITES = Set.of(
        "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
        "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC",
        "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
        "GOST2012-GOST8912-GOST8912",
        "GOST2012-KUZNYECHIK-KUZNYECHIKОМАС",
        "GOST2012",
        "GOST"
    );
    
    // КРИТИЧНО слабые cipher suites (только явно уязвимые!)
    private static final Set<String> CRITICAL_WEAK_SUITES = Set.of(
        "SSL_", "TLS_RSA_WITH_NULL", "TLS_NULL", "DES", "RC4",
        "MD5", "EXPORT", "ANON"
    );
    
    // КРИТИЧНО слабые TLS (только явно уязвимые!)
    private static final Set<String> CRITICAL_WEAK_TLS = Set.of(
        "SSLv2", "SSLv3", "TLSv1", "TLSv1.1"
    );
    
    private final String targetUrl;
    
    public TLSAnalyzer(String targetUrl) {
        this.targetUrl = targetUrl;
    }
    
    /**
     * Анализ TLS соединения с сервером
     */
    public List<Vulnerability> analyzeTLS() {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (targetUrl == null || !targetUrl.startsWith("https://")) {
            log.warn("URL не HTTPS, пропускаем TLS анализ");
            return vulnerabilities;
        }
        
        try {
            log.info("Анализ TLS для: {}", targetUrl);
            
            URL url = new URL(targetUrl);
            String host = url.getHost();
            int port = url.getPort() != -1 ? url.getPort() : 443;
            
            // Подключаемся и анализируем
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, getTrustAllCerts(), new java.security.SecureRandom());
            
            SSLSocketFactory factory = sslContext.getSocketFactory();
            
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                socket.startHandshake();
                
                SSLSession session = socket.getSession();
                
                // 1. Проверка протокола TLS
                vulnerabilities.addAll(checkTLSProtocol(session));
                
                // 2. Проверка cipher suite
                vulnerabilities.addAll(checkCipherSuite(session));
                
                // 3. Проверка сертификата
                vulnerabilities.addAll(checkCertificates(session, host));
                
                log.info("TLS анализ завершен. Найдено проблем: {}", vulnerabilities.size());
                
            }
            
        } catch (Exception e) {
            log.error("Ошибка при TLS анализе: {}", e.getMessage());
            
            // Это тоже уязвимость - не можем подключиться по HTTPS
            vulnerabilities.add(Vulnerability.builder()
                .id("TLS-CONNECT-ERROR")
                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.HIGH)
                .title("Невозможно установить HTTPS соединение")
                .description("Не удалось подключиться к " + targetUrl + " по HTTPS: " + e.getMessage())
                .endpoint(targetUrl)
                .method("N/A")
                .recommendation("Проверьте конфигурацию TLS/SSL на сервере")
                .owaspCategory("API8:2023 - Security Misconfiguration")
                .evidence("Exception: " + e.getClass().getSimpleName())
                .build());
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка версии TLS - ТОЛЬКО критично уязвимые!
     */
    private List<Vulnerability> checkTLSProtocol(SSLSession session) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        String protocol = session.getProtocol();
        log.info("TLS Protocol: {}", protocol);
        
        // Проверка ТОЛЬКО на критично слабые версии (SSLv2, SSLv3, TLS 1.0, 1.1)
        if (CRITICAL_WEAK_TLS.stream().anyMatch(weak -> weak.equalsIgnoreCase(protocol))) {
            vulnerabilities.add(Vulnerability.builder()
                .id("TLS-CRITICAL-WEAK")
                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.CRITICAL)
                .title("КРИТИЧНО! Устаревшая версия TLS с известными уязвимостями")
                .description(
                    "Сервер использует " + protocol + " - подвержен атакам:\n" +
                    "• POODLE (SSLv3)\n" +
                    "• BEAST (TLS 1.0)\n" +
                    "• Lucky 13 (TLS 1.0/1.1)\n\n" +
                    "Эти протоколы ЗАПРЕЩЕНЫ стандартами безопасности!"
                )
                .endpoint(targetUrl)
                .method("N/A")
                .recommendation(
                    "НЕМЕДЛЕННО отключите устаревшие протоколы!\n\n" +
                    "Минимум: TLS 1.2 с ГОСТ cipher suites\n" +
                    "Рекомендуется: TLS 1.3 с ГОСТ\n\n" +
                    "Конфигурация (Nginx):\n" +
                    "ssl_protocols TLSv1.2 TLSv1.3;\n" +
                    "ssl_ciphers GOST2012-GOST8912-GOST8912:TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC;"
                )
                .owaspCategory("API8:2023 - Security Misconfiguration")
                .evidence("Protocol: " + protocol + " (КРИТИЧНО УСТАРЕВШИЙ!)")
                .gostRelated(true)
                .build());
        } else {
            log.info("TLS Protocol OK: {}", protocol);
        }
        return vulnerabilities;
    }
    
    /**
     * Проверка cipher suite - ФОКУС ТОЛЬКО НА ГОСТ!
     * Международные алгоритмы НЕ проверяем (не наша задача)
     */
    private List<Vulnerability> checkCipherSuite(SSLSession session) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        String cipherSuite = session.getCipherSuite();
        log.info("🔐 Cipher Suite: {}", cipherSuite);
        
        // 1. Проверка КРИТИЧНО слабых (NULL, RC4, DES - явно уязвимые!)
        for (String weak : CRITICAL_WEAK_SUITES) {
            if (cipherSuite.toUpperCase().contains(weak)) {
                vulnerabilities.add(Vulnerability.builder()
                    .id("GOST-CRITICAL-WEAK-CIPHER")
                    .type(VulnerabilityType.GOST_VIOLATION)
                    .severity(Severity.CRITICAL)
                    .title("КРИТИЧНО! Используется уязвимый cipher suite")
                    .description(
                        "Cipher suite " + cipherSuite + " содержит КРИТИЧНО слабый алгоритм: " + weak + "\n\n" +
                        "Это ЗАПРЕЩЕНО:\n" +
                        "• Приказ ФСБ России №378\n" +
                        "• Требования ЦБ РФ для банков\n" +
                        "• Стандарты информационной безопасности РФ"
                    )
                    .endpoint(targetUrl)
                    .method("N/A")
                    .recommendation(
                        "НЕМЕДЛЕННО отключите слабые cipher suites!\n\n" +
                        "Используйте ТОЛЬКО ГОСТ cipher suites:\n" +
                        "• TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC\n" +
                        "• TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC\n\n" +
                        "Настройка (Nginx):\n" +
                        "ssl_ciphers GOST2012-GOST8912-GOST8912;\n" +
                        "ssl_prefer_server_ciphers on;"
                    )
                    .owaspCategory("Russian Standards - GOST (CRITICAL)")
                    .evidence("Cipher: " + cipherSuite + " содержит " + weak)
                    .gostRelated(true)
                    .build());
                break;
            }
        }
        
        // 2. ГЛАВНОЕ - Проверка ГОСТ cipher suites
        boolean hasGostCipher = GOST_CIPHER_SUITES.stream()
            .anyMatch(gost -> cipherSuite.toUpperCase().contains(gost.toUpperCase()) || 
                             cipherSuite.toUpperCase().contains("GOST"));
        
        if (!hasGostCipher) {
            // ВСЕГДА проверяем ГОСТ! Неважно какой API!
            vulnerabilities.add(Vulnerability.builder()
                .id("GOST-NO-CIPHER-SUITE")
                .type(VulnerabilityType.GOST_VIOLATION)
                .severity(Severity.HIGH)
                .title("Не используются ГОСТ TLS cipher suites")
                .description(
                    "Сервер использует cipher suite: " + cipherSuite + "\n\n" +
                    "Это НЕ ГОСТ Р 34.10-2012!\n\n" +
                    "Для соответствия российским требованиям информационной безопасности:\n" +
                    "• Приказ ФСБ России №378 от 2005г\n" +
                    "• ГОСТ Р 34.10-2012 - обязателен для:\n" +
                    "  - Государственных систем\n" +
                    "  - Банковского сектора\n" +
                    "  - Критической инфраструктуры\n" +
                    "  - Персональных данных (ФЗ-152)\n\n" +
                    "Используемый cipher (" + cipherSuite + ") не соответствует российским стандартам."
                )
                .endpoint(targetUrl)
                .method("N/A")
                .recommendation(
                    "Настройте TLS с ГОСТ cipher suites:\n\n" +
                    "1. ГОСТ Р 34.10-2012 cipher suites:\n" +
                    "   • TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC (рекомендуется!)\n" +
                    "   • TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC\n" +
                    "   • TLS_GOSTR341112_256_WITH_28147_CNT_IMIT\n\n" +
                    "2. Реализация:\n" +
                    "   Java:\n" +
                    "     - BouncyCastle 1.70+\n" +
                    "     - CryptoPro JCP 2.0\n" +
                    "   \n" +
                    "   Nginx/Apache:\n" +
                    "     - OpenSSL с engine_gost\n" +
                    "     - Патчи ГОСТ для TLS\n\n" +
                    "3. Пример конфигурации Nginx:\n" +
                    "   ssl_protocols TLSv1.2 TLSv1.3;\n" +
                    "   ssl_ciphers GOST2012-GOST8912-GOST8912:GOST2012-KUZNYECHIK-KUZNYECHIKОМАС;\n" +
                    "   ssl_prefer_server_ciphers on;\n\n" +
                    "4. Получение сертификата:\n" +
                    "   - От аккредитованного ФСБ УЦ (см. ниже)"
                )
                .owaspCategory("Russian Standards - ГОСТ Р 34.10-2012")
                .evidence("Current: " + cipherSuite + " | Required: ГОСТ cipher suites")
                .gostRelated(true)
                .build());
        } else {
            log.info("ОТЛИЧНО! ГОСТ cipher suite обнаружен: {}", cipherSuite);
        }
        
        return vulnerabilities;
    }
    
    /**
     * Проверка сертификатов - ФОКУС НА ГОСТ!
     */
    private List<Vulnerability> checkCertificates(SSLSession session, String expectedHost) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        try {
            Certificate[] certs = session.getPeerCertificates();
            
            if (certs == null || certs.length == 0) {
                return vulnerabilities; // Пропускаем если нет сертификата
            }
            
            X509Certificate cert = (X509Certificate) certs[0];
            
            // 1. Проверка срока действия (критично!)
            try {
                cert.checkValidity();
            } catch (Exception e) {
                vulnerabilities.add(Vulnerability.builder()
                    .id("TLS-CERT-EXPIRED")
                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                    .severity(Severity.CRITICAL)
                    .title("Сертификат истек или еще не действителен")
                    .description("SSL сертификат недействителен: " + e.getMessage())
                    .endpoint(targetUrl)
                    .method("N/A")
                    .recommendation("Обновите SSL сертификат с ГОСТ Р 34.10-2012")
                    .owaspCategory("API8:2023 - Security Misconfiguration")
                    .evidence("Certificate validity error")
                    .gostRelated(true)
                    .build());
            }
            
            // 2. ГЛАВНОЕ: Проверка алгоритма подписи на ГОСТ!
            String sigAlg = cert.getSigAlgName();
            String issuer = cert.getIssuerX500Principal().getName();
            log.info("Signature Algorithm: {}", sigAlg);
            log.info("Issuer: {}", issuer);
            
            boolean hasGostSig = sigAlg.toUpperCase().contains("GOST") ||
                                sigAlg.contains("34.10") ||
                                sigAlg.contains("34.11");
            
            // Проверка российского УЦ
            boolean isRussianCA = RussianCAValidator.isRussianAccreditedCA(issuer);
            
            if (!hasGostSig) {
                vulnerabilities.add(Vulnerability.builder()
                    .id("GOST-CERT-SIG")
                    .type(VulnerabilityType.GOST_VIOLATION)
                    .severity(Severity.HIGH)
                    .title("Сертификат подписан БЕЗ ГОСТ алгоритма")
                    .description(
                        "SSL сертификат использует " + sigAlg + " для подписи (международный стандарт). " +
                        "Для соответствия российским требованиям информационной безопасности " +
                        "ОБЯЗАТЕЛЬНО использование ГОСТ Р 34.10-2012 для ЭЦП."
                    )
                    .endpoint(targetUrl)
                    .method("N/A")
                    .recommendation(RussianCAValidator.getRecommendation())
                    .owaspCategory("Russian Standards - GOST")
                    .evidence("Signature Algorithm: " + sigAlg + " (НЕ ГОСТ Р 34.10-2012)")
                    .gostRelated(true)
                    .build());
            } else {
                log.info("ГОСТ сертификат обнаружен! Signature: {}", sigAlg);
            }
            
            // 3. Проверка российского УЦ (chain of trust)
            if (!isRussianCA && !hasGostSig) {
                vulnerabilities.add(Vulnerability.builder()
                    .id("GOST-FOREIGN-CA")
                    .type(VulnerabilityType.GOST_VIOLATION)
                    .severity(Severity.MEDIUM)
                    .title("Сертификат выдан зарубежным УЦ")
                    .description(
                        "Сертификат выдан: " + issuer + "\n" +
                        "Это не аккредитованный ФСБ России удостоверяющий центр. " +
                        "Для государственных систем требуются сертификаты от российских УЦ."
                    )
                    .endpoint(targetUrl)
                    .method("N/A")
                    .recommendation(RussianCAValidator.getRecommendation())
                    .owaspCategory("Russian Standards - GOST")
                    .evidence("Issuer: " + issuer)
                    .gostRelated(true)
                    .build());
            } else if (isRussianCA) {
                log.info("Сертификат от российского УЦ: {}", issuer);
            }
            
        } catch (Exception e) {
            log.error("Ошибка при проверке сертификатов: {}", e.getMessage());
        }
        
        return vulnerabilities;
    }
    
    /**
     * TrustManager который принимает все сертификаты (для анализа)
     */
    private TrustManager[] getTrustAllCerts() {
        return new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }
        };
    }
    
    /**
     * Проверка hostname
     */
    private boolean verifyHostname(X509Certificate cert, String expectedHost) {
        try {
            // Упрощенная проверка CN
            String subject = cert.getSubjectX500Principal().getName();
            return subject.contains("CN=" + expectedHost) || 
                   subject.contains("CN=*." + expectedHost.substring(expectedHost.indexOf('.') + 1));
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Получить детальную информацию о TLS (для отчетов)
     */
    public Map<String, String> getTLSInfo() {
        Map<String, String> info = new HashMap<>();
        
        if (targetUrl == null || !targetUrl.startsWith("https://")) {
            return info;
        }
        
        try {
            URL url = new URL(targetUrl);
            String host = url.getHost();
            int port = url.getPort() != -1 ? url.getPort() : 443;
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, getTrustAllCerts(), new java.security.SecureRandom());
            
            try (SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket(host, port)) {
                socket.startHandshake();
                SSLSession session = socket.getSession();
                
                info.put("protocol", session.getProtocol());
                info.put("cipherSuite", session.getCipherSuite());
                
                X509Certificate cert = (X509Certificate) session.getPeerCertificates()[0];
                info.put("subject", cert.getSubjectX500Principal().getName());
                info.put("issuer", cert.getIssuerX500Principal().getName());
                info.put("signatureAlgorithm", cert.getSigAlgName());
                info.put("notBefore", cert.getNotBefore().toString());
                info.put("notAfter", cert.getNotAfter().toString());
                
                // Проверка ГОСТ
                boolean hasGost = info.get("signatureAlgorithm").toUpperCase().contains("GOST") ||
                                 info.get("cipherSuite").toUpperCase().contains("GOST");
                info.put("gostCompliant", String.valueOf(hasGost));
            }
            
        } catch (Exception e) {
            info.put("error", e.getMessage());
        }
        
        return info;
    }
}

