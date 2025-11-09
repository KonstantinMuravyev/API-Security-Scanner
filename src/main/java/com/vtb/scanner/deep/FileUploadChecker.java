package com.vtb.scanner.deep;

import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityType;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * Проверка безопасности File Upload
 * 
 * Риски:
 * - Unlimited file size (DoS)
 * - Dangerous file types (.exe, .php, .jsp)
 * - No virus scanning
 * - Path traversal в filename
 */
@Slf4j
public class FileUploadChecker {
    
    private static final Set<String> DANGEROUS_FILE_TYPES = Set.of(
        "application/x-executable",
        "application/x-sh",
        "application/x-php",
        "application/x-jsp",
        "text/html",
        "text/javascript",
        "application/java-archive" // .jar
    );
    
    public static List<Vulnerability> checkFileUploads(OpenAPI openAPI) {
        log.info("Проверка File Upload безопасности...");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // КРИТИЧНО: Защита от NPE
        if (openAPI == null || openAPI.getPaths() == null) return vulnerabilities;
        
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // POST/PUT обычно для uploads
            if (pathItem.getPost() != null) {
                vulnerabilities.addAll(checkOperation(path, "POST", pathItem.getPost()));
            }
            if (pathItem.getPut() != null) {
                vulnerabilities.addAll(checkOperation(path, "PUT", pathItem.getPut()));
            }
        }
        
        log.info("File Upload проверка завершена. Найдено: {}", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private static List<Vulnerability> checkOperation(String path, String method, Operation operation) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (operation.getRequestBody() == null || 
            operation.getRequestBody().getContent() == null) {
            return vulnerabilities;
        }
        
        Content content = operation.getRequestBody().getContent();
        
        // Проверяем multipart/form-data (file upload!)
        MediaType multipart = content.get("multipart/form-data");
        if (multipart != null && multipart.getSchema() != null) {
            Schema schema = multipart.getSchema();
            
            // 1. Проверка ограничения размера
            if (schema.getMaxLength() == null && schema.getMaxProperties() == null) {
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION, path, method, null,
                        "Нет ограничения размера файла"))
                    .type(VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION)
                    .severity(Severity.HIGH)
                    .title("Нет ограничения размера файла")
                    .description(
                        "Endpoint " + path + " принимает файлы БЕЗ ограничения размера!\n\n" +
                        "Риски:\n" +
                        "• DoS через загрузку огромных файлов\n" +
                        "• Заполнение диска\n" +
                        "• Out of Memory"
                    )
                    .endpoint(path)
                    .method(method)
                    .recommendation(
                        "Установите лимиты:\n\n" +
                        "1. Максимальный размер файла (например, 10 MB)\n" +
                        "2. Content-Length header проверка\n" +
                        "3. Stream processing (не загружать весь файл в память)\n\n" +
                        "В OpenAPI:\n" +
                        "schema:\n" +
                        "  type: string\n" +
                        "  format: binary\n" +
                        "  maxLength: 10485760  # 10 MB"
                    )
                    .owaspCategory("API4:2023 - Unrestricted Resource Consumption")
                    .evidence("multipart/form-data без maxLength")
                    .build());
            }
            
            // 2. Проверка типов файлов
            String desc = operation.getDescription() != null ? operation.getDescription().toLowerCase() : "";
            if (!desc.contains("allowed") && !desc.contains("whitelist") && 
                !desc.contains("validation")) {
                
                vulnerabilities.add(Vulnerability.builder()
                    .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                        VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, null,
                        "Нет валидации типов файлов"))
                    .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                    .severity(Severity.MEDIUM)
                    .title("Нет валидации типов файлов")
                    .description(
                        "Endpoint " + path + " принимает файлы БЕЗ проверки типа!\n\n" +
                        "Риски:\n" +
                        "• Загрузка .exe, .sh (вирусы!)\n" +
                        "• .php, .jsp (webshell!)\n" +
                        "• .html (stored XSS!)"
                    )
                    .endpoint(path)
                    .method(method)
                    .recommendation(
                        "Валидация файлов:\n\n" +
                        "1. Whitelist расширений: только .jpg, .png, .pdf\n" +
                        "2. MIME type проверка (не доверять расширению!)\n" +
                        "3. Magic bytes проверка\n" +
                        "4. Антивирус сканирование\n" +
                        "5. Sanitize filename (защита от path traversal)"
                    )
                    .owaspCategory("API8:2023 - Security Misconfiguration")
                    .evidence("File upload без валидации типов")
                    .build());
            }
        }
        
        // Проверяем application/octet-stream (binary upload)
        if (content.containsKey("application/octet-stream")) {
            vulnerabilities.add(Vulnerability.builder()
                .id(com.vtb.scanner.models.VulnerabilityIdGenerator.generateId(
                    VulnerabilityType.SECURITY_MISCONFIGURATION, path, method, null,
                    "Принимает произвольные бинарные файлы"))
                .type(VulnerabilityType.SECURITY_MISCONFIGURATION)
                .severity(Severity.MEDIUM)
                .title("Принимает произвольные бинарные файлы")
                .description(
                    "Endpoint принимает application/octet-stream - любые бинарные данные!\n\n" +
                    "Это опасно если нет валидации."
                )
                .endpoint(path)
                .method(method)
                .recommendation("Используйте конкретные MIME types или строгую валидацию")
                .owaspCategory("API8:2023 - Security Misconfiguration")
                .evidence("application/octet-stream без ограничений")
                .build());
        }
        
        return vulnerabilities;
    }
}

