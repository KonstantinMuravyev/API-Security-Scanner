package com.vtb.scanner.integration;

import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.semantic.ContextAnalyzer;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.*;
import java.net.InetSocketAddress;
import java.net.URI;
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
    
    private static final String[] PROTOCOLS_TO_PROBE = {"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"};
    private static final String[] WEAK_CIPHER_PROBES = {
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_NULL_SHA"
    };
    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int SOCKET_TIMEOUT_MS = 5000;
    
    private final String targetUrl;
    private final ContextAnalyzer.APIContext apiContext;
    private final boolean enforceGost;
    private transient HandshakeResult lastHandshake;
    private transient TlsProbeReport lastProbeReport;
    
    public TLSAnalyzer(String targetUrl) {
        this(targetUrl, ContextAnalyzer.APIContext.GENERAL, true);
    }

    public TLSAnalyzer(String targetUrl, ContextAnalyzer.APIContext apiContext, boolean enforceGost) {
        this.targetUrl = targetUrl;
        this.apiContext = apiContext != null ? apiContext : ContextAnalyzer.APIContext.GENERAL;
        this.enforceGost = enforceGost;
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

            HostPort hostPort = resolveHostPort();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, getTrustAllCerts(), new java.security.SecureRandom());
            SSLSocketFactory factory = sslContext.getSocketFactory();

            HandshakeResult handshakeResult = performDefaultHandshake(factory, hostPort.host(), hostPort.port());
            this.lastHandshake = handshakeResult;

            if (handshakeResult.session == null) {
                vulnerabilities.add(Vulnerability.builder()
                    .id("TLS-CONNECT-ERROR")
                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                    .severity(Severity.HIGH)
                    .title("Невозможно установить HTTPS соединение")
                    .description("Не удалось подключиться к " + targetUrl + " по HTTPS: " +
                        (handshakeResult.errorMessage != null ? handshakeResult.errorMessage : "unknown error"))
                    .endpoint(targetUrl)
                    .method("N/A")
                    .recommendation("Проверьте конфигурацию TLS/SSL на сервере")
                    .owaspCategory("API8:2023 - Security Misconfiguration")
                    .evidence("Exception: " + handshakeResult.exceptionClass)
                    .build());
                return vulnerabilities;
            }

            SSLSession session = handshakeResult.session;

            vulnerabilities.addAll(checkTLSProtocol(session));

            TlsProbeReport probeReport = probeServer(factory, hostPort.host(), hostPort.port());
            this.lastProbeReport = probeReport;

            vulnerabilities.addAll(checkCipherSuite(session, probeReport));

            vulnerabilities.addAll(checkCertificates(session, hostPort.host()));

            vulnerabilities.addAll(analyzeProbeReport(probeReport, session.getProtocol()));

            log.info("TLS анализ завершен. Найдено проблем: {}", vulnerabilities.size());
            
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
    private List<Vulnerability> checkCipherSuite(SSLSession session, TlsProbeReport report) {
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
        
        boolean serverSupportsGost = report != null && !report.supportedGostSuites.isEmpty();
        boolean clientCouldNotTestGost = report != null && !report.clientSupportsGost;

        if (!hasGostCipher && !serverSupportsGost) {
            Severity severity = adjustGostSeverity(Severity.HIGH);
            if (severity == null) {
                return vulnerabilities;
            }
            vulnerabilities.add(Vulnerability.builder()
                .id("GOST-NO-CIPHER-SUITE")
                .type(VulnerabilityType.GOST_VIOLATION)
                .severity(severity)
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
                .evidence(buildGostEvidence(cipherSuite, report, clientCouldNotTestGost))
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
                Severity severity = adjustGostSeverity(Severity.HIGH);
                if (severity != null) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id("GOST-CERT-SIG")
                        .type(VulnerabilityType.GOST_VIOLATION)
                        .severity(severity)
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
                }
            } else {
                log.info("ГОСТ сертификат обнаружен! Signature: {}", sigAlg);
            }
            
            // 3. Проверка российского УЦ (chain of trust)
            if (!isRussianCA && !hasGostSig) {
                Severity severity = adjustGostSeverity(Severity.MEDIUM);
                if (severity != null) {
                    vulnerabilities.add(Vulnerability.builder()
                        .id("GOST-FOREIGN-CA")
                        .type(VulnerabilityType.GOST_VIOLATION)
                        .severity(severity)
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
                }
            } else if (isRussianCA) {
                log.info("Сертификат от российского УЦ: {}", issuer);
            }

            if (!verifyHostname(cert, expectedHost)) {
                vulnerabilities.add(Vulnerability.builder()
                    .id("TLS-HOSTNAME-MISMATCH")
                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                    .severity(Severity.HIGH)
                    .title("Сертификат не соответствует имени хоста")
                    .description("Имя в сертификате не совпадает с запрошенным хостом: " + expectedHost)
                    .endpoint(targetUrl)
                    .method("N/A")
                    .recommendation("Переиздайте сертификат с корректным CN/SAN для " + expectedHost)
                    .owaspCategory("API8:2023 - Security Misconfiguration")
                    .evidence("Certificate Subject: " + cert.getSubjectX500Principal().getName())
                    .build());
            }
            
        } catch (Exception e) {
            log.error("Ошибка при проверке сертификатов: {}", e.getMessage());
        }
        
        return vulnerabilities;
    }
    
    private String buildGostEvidence(String cipherSuite, TlsProbeReport report, boolean clientCouldNotTestGost) {
        StringBuilder builder = new StringBuilder();
        builder.append("Negotiated cipher: ").append(cipherSuite);
        if (report != null) {
            if (!report.supportedGostSuites.isEmpty()) {
                builder.append(". Сервер поддерживает ГОСТ cipher suites: ").append(String.join(", ", report.supportedGostSuites));
            } else if (clientCouldNotTestGost) {
                builder.append(". Проверка ГОСТ cipher suites не выполнена — JVM клиента не поддерживает ГОСТ.");
            } else if (!report.gostErrors.isEmpty()) {
                builder.append(". Попытки согласовать ГОСТ cipher suites завершились ошибкой: ").append(report.gostErrors);
            } else {
                builder.append(". ГОСТ cipher suites не обнаружены во время проб.");
            }
        }
        return builder.toString();
    }

    private Severity adjustGostSeverity(Severity defaultSeverity) {
        if (defaultSeverity == null) {
            return null;
        }
        if (enforceGost) {
            return defaultSeverity;
        }
        return switch (apiContext) {
            case BANKING, GOVERNMENT, HEALTHCARE -> defaultSeverity; // shouldn't happen when enforceGost=false
            case TELECOM, AUTOMOTIVE -> downgrade(defaultSeverity, Severity.MEDIUM);
            case ECOMMERCE, SOCIAL, IOT -> downgrade(defaultSeverity, Severity.LOW);
            case GENERAL -> downgrade(defaultSeverity, Severity.LOW);
        };
    }

    private Severity downgrade(Severity current, Severity floor) {
        Severity downgraded = switch (current) {
            case CRITICAL -> Severity.HIGH;
            case HIGH -> Severity.MEDIUM;
            case MEDIUM -> Severity.LOW;
            default -> current;
        };
        if (downgraded.compareTo(floor) < 0) {
            return floor;
        }
        return downgraded;
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
    
    private HandshakeResult performDefaultHandshake(SSLSocketFactory factory, String host, int port) {
        HandshakeResult result = new HandshakeResult();
        try (SSLSocket socket = createSocket(factory, host, port, null, null)) {
            SSLSession session = socket.getSession();
            result.session = session;
        } catch (Exception e) {
            result.errorMessage = e.getMessage();
            result.exceptionClass = e.getClass().getSimpleName();
        }
        return result;
    }

    private TlsProbeReport probeServer(SSLSocketFactory factory, String host, int port) {
        TlsProbeReport report = new TlsProbeReport();
        try {
            try (SSLSocket socket = createSocket(factory, host, port, null, null)) {
                SSLSession session = socket.getSession();
                report.negotiatedCipherSuites.add(session.getCipherSuite());
                report.supportedProtocols.add(session.getProtocol());
            } catch (Exception e) {
                report.generalError = e.getMessage();
            }

            for (String protocol : PROTOCOLS_TO_PROBE) {
                try (SSLSocket socket = createSocket(factory, host, port, new String[]{protocol}, null)) {
                    SSLSession session = socket.getSession();
                    String negotiatedProtocol = session.getProtocol();
                    report.supportedProtocols.add(negotiatedProtocol);
                    if (CRITICAL_WEAK_TLS.stream().anyMatch(p -> p.equalsIgnoreCase(negotiatedProtocol))) {
                        report.insecureProtocols.add(negotiatedProtocol);
                    }
                } catch (Exception e) {
                    report.protocolErrors.put(protocol, e.getMessage());
                }
            }

            String[] clientSupportedSuites = factory.getSupportedCipherSuites();
            report.clientSupportsGost = Arrays.stream(clientSupportedSuites)
                .anyMatch(s -> s.toUpperCase(Locale.ROOT).contains("GOST"));

            for (String gostSuite : GOST_CIPHER_SUITES) {
                if (!Arrays.asList(clientSupportedSuites).contains(gostSuite)) {
                    report.clientMissingGostSuites.add(gostSuite);
                    continue;
                }
                try (SSLSocket socket = createSocket(factory, host, port, new String[]{"TLSv1.2", "TLSv1.3"}, new String[]{gostSuite})) {
                    SSLSession session = socket.getSession();
                    report.supportedGostSuites.add(session.getCipherSuite());
                } catch (Exception e) {
                    report.gostErrors.put(gostSuite, e.getMessage());
                }
            }

            for (String weakSuite : WEAK_CIPHER_PROBES) {
                if (!Arrays.asList(clientSupportedSuites).contains(weakSuite)) {
                    continue;
                }
                try (SSLSocket socket = createSocket(factory, host, port, new String[]{"TLSv1.2", "TLSv1.1", "TLSv1"}, new String[]{weakSuite})) {
                    SSLSession session = socket.getSession();
                    report.acceptedWeakSuites.add(session.getCipherSuite());
                } catch (Exception e) {
                    // Сервер не принял слабый suite — игнорируем
                }
            }
        } catch (Exception e) {
            report.generalError = e.getMessage();
        }
        return report;
    }

    private List<Vulnerability> analyzeProbeReport(TlsProbeReport report, String negotiatedProtocol) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        if (report == null) {
            return vulnerabilities;
        }

        for (String protocol : report.insecureProtocols) {
            if (negotiatedProtocol != null && protocol.equalsIgnoreCase(negotiatedProtocol)) {
                continue;
            }
            vulnerabilities.add(Vulnerability.builder()
                .id("TLS-LEGACY-PROTOCOL")
                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.CRITICAL)
                .title("Сервер поддерживает устаревший протокол TLS")
                .description("Сервер допускает использование протокола " + protocol + ", что раскрывает атаку POODLE/BEAST/Lucky13.")
                .endpoint(targetUrl)
                .method("N/A")
                .recommendation("Отключите поддержку " + protocol + ". Минимально допустимый уровень — TLS 1.2.")
                .owaspCategory("API8:2023 - Security Misconfiguration")
                .evidence("Дополнительный анализ: сервер согласовал " + protocol)
                .build());
        }

        if (!report.acceptedWeakSuites.isEmpty()) {
            vulnerabilities.add(Vulnerability.builder()
                .id("TLS-WEAK-CIPHER-ACCEPTED")
                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.CRITICAL)
                .title("Сервер принимает слабые TLS cipher suites")
                .description("TLS сервер согласовывает слабые cipher suites: " + String.join(", ", report.acceptedWeakSuites))
                .endpoint(targetUrl)
                .method("N/A")
                .recommendation("Запретите поддержку устаревших cipher suites (RC4, 3DES, NULL). Используйте современные ГОСТ или TLS 1.3.")
                .owaspCategory("API8:2023 - Security Misconfiguration")
                .evidence("Accepted weak suites: " + String.join(", ", report.acceptedWeakSuites))
                .build());
        }

        return vulnerabilities;
    }

    private SSLSocket createSocket(SSLSocketFactory factory,
                                   String host,
                                   int port,
                                   String[] requestedProtocols,
                                   String[] requestedSuites) throws Exception {
        SSLSocket socket = (SSLSocket) factory.createSocket();
        socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
        socket.setSoTimeout(SOCKET_TIMEOUT_MS);

        if (requestedProtocols != null) {
            Set<String> supported = new HashSet<>(Arrays.asList(socket.getSupportedProtocols()));
            List<String> enabled = new ArrayList<>();
            for (String protocol : requestedProtocols) {
                if (supported.contains(protocol)) {
                    enabled.add(protocol);
                }
            }
            if (!enabled.isEmpty()) {
                socket.setEnabledProtocols(enabled.toArray(new String[0]));
            }
        }

        if (requestedSuites != null) {
            Set<String> supportedSuites = new HashSet<>(Arrays.asList(socket.getSupportedCipherSuites()));
            List<String> enabledSuites = new ArrayList<>();
            for (String suite : requestedSuites) {
                if (supportedSuites.contains(suite)) {
                    enabledSuites.add(suite);
                }
            }
            if (enabledSuites.isEmpty()) {
                throw new SSLHandshakeException("Requested cipher suites not supported by client");
            }
            socket.setEnabledCipherSuites(enabledSuites.toArray(new String[0]));
        }

        socket.startHandshake();
        return socket;
    }

    private HostPort resolveHostPort() throws Exception {
        URI uri = new URI(targetUrl);
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("Не удалось определить хост из URL: " + targetUrl);
        }
        int port = uri.getPort() != -1 ? uri.getPort() : 443;
        return new HostPort(host, port);
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
            HostPort hostPort = resolveHostPort();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, getTrustAllCerts(), new java.security.SecureRandom());
            SSLSocketFactory factory = sslContext.getSocketFactory();

            HandshakeResult handshake = (lastHandshake != null && lastHandshake.session != null)
                ? lastHandshake
                : performDefaultHandshake(factory, hostPort.host(), hostPort.port());

            if (handshake.session != null) {
                info.put("protocol", handshake.session.getProtocol());
                info.put("cipherSuite", handshake.session.getCipherSuite());
                Certificate[] certs = handshake.session.getPeerCertificates();
                if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate cert) {
                    info.put("subject", cert.getSubjectX500Principal().getName());
                    info.put("issuer", cert.getIssuerX500Principal().getName());
                    info.put("signatureAlgorithm", cert.getSigAlgName());
                    info.put("notBefore", cert.getNotBefore().toString());
                    info.put("notAfter", cert.getNotAfter().toString());
                }
            } else if (handshake.errorMessage != null) {
                info.put("handshakeError", handshake.errorMessage);
            }

            TlsProbeReport report = (lastProbeReport != null)
                ? lastProbeReport
                : probeServer(factory, hostPort.host(), hostPort.port());

            if (report.generalError != null) {
                info.put("probeError", report.generalError);
            }
            if (!report.supportedProtocols.isEmpty()) {
                info.put("supportedProtocols", String.join(", ", report.supportedProtocols));
            }
            if (!report.acceptedWeakSuites.isEmpty()) {
                info.put("acceptedWeakCipherSuites", String.join(", ", report.acceptedWeakSuites));
            } else {
                info.put("acceptedWeakCipherSuites", "none");
            }
            if (!report.supportedGostSuites.isEmpty()) {
                info.put("gostCipherSuites", String.join(", ", report.supportedGostSuites));
            } else if (!report.clientSupportsGost) {
                info.put("gostCipherSuites", "client JVM does not support ГОСТ cipher suites");
            } else {
                info.put("gostCipherSuites", "not detected");
            }
            if (!report.protocolErrors.isEmpty()) {
                info.put("protocolProbeErrors", report.protocolErrors.toString());
            }
            if (!report.gostErrors.isEmpty()) {
                info.put("gostProbeErrors", report.gostErrors.toString());
            }
            
        } catch (Exception e) {
            info.put("error", e.getMessage());
        }
        
        return info;
    }
    private record HostPort(String host, int port) { }

    private static class HandshakeResult {
        SSLSession session;
        String errorMessage;
        String exceptionClass;
    }

    private static class TlsProbeReport {
        final Set<String> supportedProtocols = new LinkedHashSet<>();
        final Set<String> insecureProtocols = new LinkedHashSet<>();
        final Set<String> supportedGostSuites = new LinkedHashSet<>();
        final Set<String> acceptedWeakSuites = new LinkedHashSet<>();
        final Map<String, String> protocolErrors = new LinkedHashMap<>();
        final Map<String, String> gostErrors = new LinkedHashMap<>();
        final Set<String> negotiatedCipherSuites = new LinkedHashSet<>();
        final Set<String> clientMissingGostSuites = new LinkedHashSet<>();
        boolean clientSupportsGost;
        String generalError;
    }
}
