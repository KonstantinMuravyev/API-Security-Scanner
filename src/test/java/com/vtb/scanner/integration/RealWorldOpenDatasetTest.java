package com.vtb.scanner.integration;

import com.vtb.scanner.core.OpenAPIParser;
import com.vtb.scanner.core.SecurityScanner;
import com.vtb.scanner.models.AttackSurfaceSummary;
import com.vtb.scanner.models.ScanResult;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Интеграционные проверки на реальных (сокращённых) OpenAPI спецификациях.
 * Наша цель — убедиться, что сканер корректно определяет контекст,
 * находит ключевые проблемы и формирует карту поверхности атаки.
 */
class RealWorldOpenDatasetTest {

    @Test
    void testGovUkNotifySpec_FindsGovernmentContextAndIssues() {
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromFile("src/test/resources/openapi-samples/real-world/govuk-notify.yaml");

        SecurityScanner scanner = new SecurityScanner(parser, "http://api.notifications.service.gov.uk", false);
        ScanResult result = scanner.scan();

        assertEquals("GOVERNMENT", result.getApiContext(), "Ожидаем контекст GOVERNMENT для GOV.UK Notify");

        List<Vulnerability> vulns = result.getVulnerabilities();
        assertFalse(vulns.isEmpty(), "Должны быть обнаружены уязвимости для GOV.UK Notify");

        boolean hasHttpFinding = vulns.stream()
            .anyMatch(v -> "MISC-HTTP".equals(v.getId()));
        assertTrue(hasHttpFinding, "Ожидаем предупреждение об использовании HTTP вместо HTTPS");

        boolean hasMisconfiguration = vulns.stream()
            .anyMatch(v -> v.getType() == VulnerabilityType.SECURITY_MISCONFIGURATION);
        assertTrue(hasMisconfiguration, "Ожидаем хотя бы одну уязвимость Security Misconfiguration");

        AttackSurfaceSummary surface = result.getAttackSurface();
        assertNotNull(surface);
        assertTrue(surface.getTotalEndpoints() >= 1, "Attack surface должен содержать описание эндпоинтов");
    }

    @Test
    void testOpenBankingSpec_ContextAndHighRiskFindings() {
        OpenAPIParser parser = new OpenAPIParser();
        parser.parseFromFile("src/test/resources/openapi-samples/real-world/openbanking-aisp.yaml");

        SecurityScanner scanner = new SecurityScanner(parser, "https://rs.openbanking.bank/sandbox", true);
        ScanResult result = scanner.scan();

        assertEquals("BANKING", result.getApiContext(), "Ожидаем контекст BANKING для Open Banking спецификации");

        List<Vulnerability> vulns = result.getVulnerabilities();
        assertFalse(vulns.isEmpty(), "Для Open Banking должны быть сгенерированы уязвимости");

        boolean hasHighSeverity = vulns.stream()
            .anyMatch(v -> v != null && v.getSeverity() != null && v.getSeverity().getPriority() >= 4);
        assertTrue(hasHighSeverity, "Должна быть как минимум одна уязвимость уровня HIGH или выше");

        boolean hasBflaOrBola = vulns.stream()
            .anyMatch(v -> v.getType() == VulnerabilityType.BFLA || v.getType() == VulnerabilityType.BOLA);
        assertTrue(hasBflaOrBola, "Ожидаем нахождение BFLA/BOLA проблем в удалении или доступе к аккаунтам");

        AttackSurfaceSummary surface = result.getAttackSurface();
        assertNotNull(surface);
        assertTrue(surface.getEntryPointCount() >= 1, "Attack surface должен содержать хотя бы одну точку входа");
    }
}

