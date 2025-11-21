package com.vtb.scanner.deep;

import com.vtb.scanner.heuristics.ConfidenceCalculator;
import com.vtb.scanner.heuristics.SmartAnalyzer;
import com.vtb.scanner.models.Severity;
import com.vtb.scanner.models.Vulnerability;
import com.vtb.scanner.models.VulnerabilityIdGenerator;
import com.vtb.scanner.models.VulnerabilityType;
import com.vtb.scanner.semantic.ContextAnalyzer;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.Encoding;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;

import java.util.*;
import java.util.stream.Collectors;

public class FileUploadChecker {
    
    private static final Set<String> DANGEROUS_FILE_TYPES = Set.of(
        "application/x-executable",
        "application/x-sh",
        "application/x-php",
        "application/x-jsp",
        "text/html",
        "text/javascript",
        "application/java-archive"
    );

    private static final Set<String> ANTIVIRUS_KEYWORDS = Set.of("virus", "antivirus", "malware", "clamav", "scan", "security scan", "sandbox");
    private static final Set<String> FILENAME_SANITIZE_KEYWORDS = Set.of("sanitize", "clean filename", "strip path", "path traversal", "normalize");
    private static final Set<String> SIZE_EXTENSION_KEYS = Set.of("x-max-file-size", "x-file-size", "x-max-filesize", "x-limit-size", "x-max-length");
    private static final Set<String> FIRMWARE_KEYWORDS = Set.of("firmware", "ota", "over-the-air", "flash", "binary update", "telematics", "vehicle", "ecu", "vin", "lada", "connected car", "remote start");
    private static final Set<String> TELECOM_KEYWORDS = Set.of("msisdn", "subscriber", "sim", "sbermobile", "telecom", "operator", "roaming", "tariff");
    private static final Set<String> SIGNATURE_KEYWORDS = Set.of("signature", "signed", "checksum", "hash", "sha256", "sha-256", "hash sum", "digital signature", "kval", "gost", "qseal", "integrity", "verification", "certificate");
    private static final Set<String> FIRMWARE_POINTER_KEYWORDS = Set.of("firmware", "ota", "binary", "telematics", "vehicle", "package", "bundle", "image", "ecu", "vin");
    private static final Set<String> BINARY_CONTENT_TYPES = Set.of("application/octet-stream", "application/x-binary", "application/x-firmware");
    private static final Set<String> ARCHIVE_CONTENT_TYPES = Set.of("application/zip", "application/x-zip-compressed", "application/gzip", "application/x-tar", "application/x-7z-compressed", "application/x-gtar");

    private FileUploadChecker() {
    }

    public static List<Vulnerability> checkFileUploads(OpenAPI openAPI,
                                                       ContextAnalyzer.APIContext context) {
        List<Vulnerability> findings = new ArrayList<>();
        if (openAPI == null || openAPI.getPaths() == null) {
            return findings;
        }
        openAPI.getPaths().forEach((path, pathItem) -> {
            if (pathItem == null) {
                return;
            }
            if (pathItem.getPost() != null) {
                analyzeOperation(findings, openAPI, context, path, "POST", pathItem.getPost());
            }
            if (pathItem.getPut() != null) {
                analyzeOperation(findings, openAPI, context, path, "PUT", pathItem.getPut());
            }
            if (pathItem.getPatch() != null) {
                analyzeOperation(findings, openAPI, context, path, "PATCH", pathItem.getPatch());
            }
        });
        return findings;
    }

    private static void analyzeOperation(List<Vulnerability> findings,
                                         OpenAPI openAPI,
                                         ContextAnalyzer.APIContext context,
                                         String path,
                                         String method,
                                         Operation operation) {
        if (operation == null || operation.getRequestBody() == null) {
            return;
        }
        Content content = operation.getRequestBody().getContent();
        if (content == null || content.isEmpty()) {
            return;
        }
        boolean highContext = context == ContextAnalyzer.APIContext.BANKING ||
            context == ContextAnalyzer.APIContext.GOVERNMENT ||
            context == ContextAnalyzer.APIContext.HEALTHCARE ||
            context == ContextAnalyzer.APIContext.TELECOM ||
            context == ContextAnalyzer.APIContext.AUTOMOTIVE;
        boolean hasFileUploads = false;

        String pathLower = Optional.ofNullable(path).orElse("").toLowerCase(Locale.ROOT);
        String combinedText = (Optional.ofNullable(operation.getSummary()).orElse("") + " " +
            Optional.ofNullable(operation.getDescription()).orElse("")).toLowerCase(Locale.ROOT);
        String operationText = (pathLower + " " + combinedText).toLowerCase(Locale.ROOT);
        boolean firmwareFlow = containsAny(operationText, FIRMWARE_KEYWORDS);
        boolean telecomFlow = containsAny(operationText, TELECOM_KEYWORDS);
        boolean signatureMentioned = containsAny(operationText, SIGNATURE_KEYWORDS);
        boolean highRiskUpload = highContext || firmwareFlow || telecomFlow;

        for (Map.Entry<String, MediaType> mediaEntry : content.entrySet()) {
            String mediaTypeName = mediaEntry.getKey();
            MediaType mediaType = mediaEntry.getValue();
            if (mediaType == null) {
                continue;
            }
            Schema<?> rootSchema = resolveSchema(mediaType.getSchema(), openAPI);
            Map<String, Encoding> encodings = mediaType.getEncoding();
            Map<String, FileField> fileFields = collectFileFields(rootSchema, openAPI, encodings);

            if (!fileFields.isEmpty()) {
                hasFileUploads = true;
            }

            for (FileField field : fileFields.values()) {
                evaluateFileField(findings, openAPI, context, path, method, operation, mediaTypeName, field, operationText, firmwareFlow, signatureMentioned);
            }

            if ("application/octet-stream".equalsIgnoreCase(mediaTypeName)) {
                addFinding(findings, openAPI, context, path, method, operation,
                    VulnerabilityType.SECURITY_MISCONFIGURATION,
                    highContext ? Severity.HIGH : Severity.MEDIUM,
                    "Принимает произвольные бинарные данные",
                    "Эндпоинт принимает application/octet-stream без дополнительных ограничений. Это позволяет загружать любой бинарный контент без валидации.",
                    "content-type: application/octet-stream",
                    "Используйте более конкретный MIME type или реализуйте строгую валидацию содержимого файла (MIME sniffing, magic bytes). Это особенно критично для чувствительных сервисов.");
            }
        }

        if (hasFileUploads) {
            Severity antivirusSeverity = firmwareFlow ? Severity.CRITICAL : (highRiskUpload ? Severity.HIGH : (highContext ? Severity.HIGH : Severity.MEDIUM));
            if (ANTIVIRUS_KEYWORDS.stream().noneMatch(combinedText::contains)) {
                addFinding(findings, openAPI, context, path, method, operation,
                    VulnerabilityType.SECURITY_MISCONFIGURATION,
                    antivirusSeverity,
                    "Не описано антивирусное сканирование загружаемых файлов",
                    "Эндпоинт принимает файлы, но в спецификации отсутствуют требования по антивирусной/малварной проверке.",
                    "summary/description без упоминаний вирусного сканирования",
                    "Добавьте в документацию и реализацию этап антивирусного сканирования (ClamAV, ICAP, sandbox). Для банков/гос сервисов это обязательное требование.");
            }
            if (FILENAME_SANITIZE_KEYWORDS.stream().noneMatch(combinedText::contains)) {
                addFinding(findings, openAPI, context, path, method, operation,
                    VulnerabilityType.SECURITY_MISCONFIGURATION,
                    highRiskUpload ? Severity.HIGH : Severity.MEDIUM,
                    "Не описана нормализация имени файла",
                    "Спецификация не содержит требований по очистке имени файла (path traversal, спецсимволы).",
                    "summary/description без sanitize/path traversal",
                    "Документируйте и реализуйте очистку имени файла: удаление ../, перевод в безопасный набор символов, генерация уникальных названий.");
            }
            if (firmwareFlow && !signatureMentioned) {
                addFinding(findings, openAPI, context, path, method, operation,
                    VulnerabilityType.SECURITY_MISCONFIGURATION,
                    Severity.CRITICAL,
                    "Загрузка прошивок без проверки подписи",
                    "Эндпоинт для OTA/firmware загрузок не содержит описания проверки цифровой подписи или контрольной суммы. Это критично для предотвращения подмены ПО.",
                    "firmware flow: " + operationText,
                    "Опишите и реализуйте проверку цифровой подписи (ГОСТ/PKI, KEP), контрольную сумму (SHA-256) и хранение ключей в защищённом контуре. Запрещайте неподписанные пакеты.");
            }
        }
    }

    private static void evaluateFileField(List<Vulnerability> findings,
                                          OpenAPI openAPI,
                                          ContextAnalyzer.APIContext context,
                                          String path,
                                          String method,
                                          Operation operation,
                                          String mediaTypeName,
                                          FileField field,
                                          String operationText,
                                          boolean firmwareContext,
                                          boolean signatureMentioned) {
        boolean highContext = context == ContextAnalyzer.APIContext.BANKING ||
            context == ContextAnalyzer.APIContext.GOVERNMENT ||
            context == ContextAnalyzer.APIContext.HEALTHCARE ||
            context == ContextAnalyzer.APIContext.TELECOM ||
            context == ContextAnalyzer.APIContext.AUTOMOTIVE;
        boolean hasSizeLimit = hasSizeLimit(field);
        if (!hasSizeLimit) {
            addFinding(findings, openAPI, context, path, method, operation,
                VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION,
                highContext ? Severity.CRITICAL : Severity.HIGH,
                "Файл '" + field.pointer + "' без ограничения размера",
                "Поле '" + field.pointer + "' принимает файл без ограничений по размеру. Это позволяет проводить DoS-атаки (загрузка огромных файлов, заполнение диска).",
                evidenceForField(field, mediaTypeName),
                "Установите maxLength или x-max-file-size для файлов, проверяйте Content-Length и реализуйте потоковую обработку. Для множественных файлов ограничьте maxItems.");
        }

        if (field.isArray && field.containerSchema != null && field.containerSchema.getMaxItems() == null) {
            addFinding(findings, openAPI, context, path, method, operation,
                VulnerabilityType.UNRESTRICTED_RESOURCE_CONSUMPTION,
                highContext ? Severity.HIGH : Severity.MEDIUM,
                "Массив файлов '" + field.pointer + "' без ограничения количества",
                "Поле '" + field.pointer + "' позволяет загружать произвольное количество файлов. Это увеличивает риск DoS.",
                evidenceForField(field, mediaTypeName),
                "Добавьте maxItems для массивов файлов и контролируйте общее количество файлов на запрос. Ограничьте параллельные загрузки и время обработки.");
        }

        List<String> allowedTypes = field.getAllowedContentTypes();
        boolean hasWhitelist = !allowedTypes.isEmpty() && allowedTypes.stream().noneMatch(t -> t.equals("*/*") || t.equalsIgnoreCase("application/octet-stream"));
        if (!hasWhitelist) {
            addFinding(findings, openAPI, context, path, method, operation,
                VulnerabilityType.SECURITY_MISCONFIGURATION,
                highContext ? Severity.HIGH : Severity.MEDIUM,
                "Файл '" + field.pointer + "' без whitelist типов",
                "Для поля '" + field.pointer + "' не определён whitelist разрешённых контент-типов. Это позволяет загрузить потенциально опасные файлы (.exe, .php, .html).",
                evidenceForField(field, mediaTypeName),
                "Определите whitelist MIME типов (например, image/png, application/pdf). Выполняйте проверку MIME, magic bytes и расширения, а также отклоняйте все прочие типы.");
        } else {
            List<String> dangerous = allowedTypes.stream()
                .map(String::toLowerCase)
                .filter(DANGEROUS_FILE_TYPES::contains)
                .collect(Collectors.toList());
            if (!dangerous.isEmpty()) {
                addFinding(findings, openAPI, context, path, method, operation,
                    VulnerabilityType.SECURITY_MISCONFIGURATION,
                    highContext ? Severity.CRITICAL : Severity.HIGH,
                    "Файл '" + field.pointer + "' разрешает опасные типы",
                    "Whitelist для поля '" + field.pointer + "' содержит опасные типы: " + dangerous + ". Это может привести к загрузке web-shell или XSS.",
                    evidenceForField(field, mediaTypeName),
                    "Исключите опасные типы (HTML, JavaScript, исполняемые файлы). Разрешайте только безопасные форматы (PDF, изображение) и проверяйте содержимое.");
            }
        }

        String pointerLower = field.pointer.toLowerCase(Locale.ROOT);
        boolean pointerFirmware = containsAny(pointerLower, FIRMWARE_POINTER_KEYWORDS);
        List<String> allowedTypesLower = field.getAllowedContentTypes().stream()
            .map(String::toLowerCase)
            .toList();
        boolean allowsBinary = allowedTypesLower.stream().anyMatch(BINARY_CONTENT_TYPES::contains);
        boolean allowsArchive = allowedTypesLower.stream().anyMatch(ARCHIVE_CONTENT_TYPES::contains);

        if ((firmwareContext || pointerFirmware) && (!signatureMentioned || allowsBinary || allowsArchive)) {
            addFinding(findings, openAPI, context, path, method, operation,
                VulnerabilityType.SECURITY_MISCONFIGURATION,
                Severity.CRITICAL,
                "Прошивка '" + field.pointer + "' без контроля целостности",
                "Поле '" + field.pointer + "' используется для OTA/firmware загрузки, но не описана проверка подписи/хэша или разрешены небезопасные типы (binary/archive).",
                evidenceForField(field, mediaTypeName),
                "Обязательно проверяйте цифровую подпись, хэш (SHA-256/ГОСТ) и блокируйте неподписанные пакеты. Храните ключи в HSM, логируйте все загрузки, ограничивайте доступ.");
        }
    }

    private static boolean hasSizeLimit(FileField field) {
        Schema<?> schema = field.fileSchema;
        if (schema == null) {
            return false;
        }
        if (schema.getMaxLength() != null && schema.getMaxLength() > 0) {
            return true;
        }
        if (field.containerSchema != null && field.containerSchema.getMaxLength() != null && field.containerSchema.getMaxLength() > 0) {
            return true;
        }
        if (field.containerSchema != null && field.containerSchema.getMaxItems() != null && field.containerSchema.getMaxItems() > 0) {
            return true;
        }
        if (hasSizeExtension(schema.getExtensions())) {
            return true;
        }
        if (field.containerSchema != null && hasSizeExtension(field.containerSchema.getExtensions())) {
            return true;
        }
        return false;
    }

    private static boolean hasSizeExtension(Map<String, Object> extensions) {
        if (extensions == null || extensions.isEmpty()) {
            return false;
        }
        for (String key : extensions.keySet()) {
            if (key != null && SIZE_EXTENSION_KEYS.contains(key.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static Map<String, FileField> collectFileFields(Schema<?> schema,
                                                            OpenAPI openAPI,
                                                            Map<String, Encoding> encodings) {
        Map<String, FileField> result = new LinkedHashMap<>();
        collectFileFieldsRecursive(schema, openAPI, encodings, "", result, new HashSet<>());
        return result;
    }

    private static void collectFileFieldsRecursive(Schema<?> schema,
                                                   OpenAPI openAPI,
                                                   Map<String, Encoding> encodings,
                                                   String pointer,
                                                   Map<String, FileField> result,
                                                   Set<Schema<?>> visited) {
        Schema<?> resolved = resolveSchema(schema, openAPI);
        if (resolved == null) {
            return;
        }
        if (!visited.add(resolved)) {
            return;
        }
        try {
            if (isFileSchema(resolved)) {
                result.put(pointer.isEmpty() ? "file" : pointer, new FileField(pointer.isEmpty() ? "file" : pointer,
                    resolved,
                    null,
                    findEncoding(encodings, pointer),
                    false));
                return;
            }
            if ("array".equals(resolved.getType())) {
                Schema<?> items = resolveSchema(resolved.getItems(), openAPI);
                if (items != null && isFileSchema(items)) {
                    String fieldPointer = pointer.isEmpty() ? "files" : pointer;
                    result.put(fieldPointer, new FileField(fieldPointer,
                        items,
                        resolved,
                        findEncoding(encodings, fieldPointer),
                        true));
                    return;
                }
                collectFileFieldsRecursive(resolved.getItems(), openAPI, encodings, pointer.isEmpty() ? "files[]" : pointer + "[]",
                    result, visited);
                return;
            }
            Map<String, Schema<?>> properties = castSchemaMap(resolved.getProperties());
            if (properties.isEmpty()) {
                return;
            }
            for (Map.Entry<String, Schema<?>> entry : properties.entrySet()) {
                String propName = entry.getKey();
                Schema<?> propSchema = entry.getValue();
                String childPointer = pointer.isEmpty() ? propName : pointer + "." + propName;
                collectFileFieldsRecursive(propSchema, openAPI, encodings, childPointer, result, visited);
            }
        } finally {
            visited.remove(resolved);
        }
    }

    private static Schema<?> resolveSchema(Schema<?> schema, OpenAPI openAPI) {
        if (schema == null) {
            return null;
        }
        if (schema.get$ref() == null) {
            return schema;
        }
        if (openAPI == null || openAPI.getComponents() == null || openAPI.getComponents().getSchemas() == null) {
            return schema;
        }
        String ref = schema.get$ref();
        String name = ref.substring(ref.lastIndexOf('/') + 1);
        Schema<?> resolved = openAPI.getComponents().getSchemas().get(name);
        return resolved != null ? resolved : schema;
    }

    private static boolean isFileSchema(Schema<?> schema) {
        if (schema == null) {
            return false;
        }
        String type = schema.getType();
        String format = schema.getFormat() != null ? schema.getFormat().toLowerCase(Locale.ROOT) : "";
        if ("string".equals(type) && ("binary".equals(format) || "byte".equals(format))) {
            return true;
        }
        if (schema.getContentMediaType() != null) {
            String media = schema.getContentMediaType().toLowerCase(Locale.ROOT);
            return media.startsWith("image/") || media.startsWith("application/") || media.startsWith("text/");
        }
        if (schema.getProperties() == null && schema.getItems() == null && "object".equals(type) && schema.getFormat() == null) {
            return false;
        }
        return false;
    }

    private static Map<String, Schema<?>> castSchemaMap(Map<?, ?> source) {
        if (source == null || source.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, Schema<?>> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            Object key = entry.getKey();
            Object value = entry.getValue();
            if (key instanceof String strKey && value instanceof Schema<?> schema) {
                result.put(strKey, schema);
            }
        }
        return result;
    }

    private static Encoding findEncoding(Map<String, Encoding> encodings, String pointer) {
        if (encodings == null || encodings.isEmpty() || pointer == null || pointer.isBlank()) {
            return null;
        }
        String firstSegment = pointer;
        int dot = firstSegment.indexOf('.');
        if (dot >= 0) {
            firstSegment = firstSegment.substring(0, dot);
        }
        if (firstSegment.endsWith("[]")) {
            firstSegment = firstSegment.substring(0, firstSegment.length() - 2);
        }
        return encodings.get(firstSegment);
    }

    private static String evidenceForField(FileField field, String mediaType) {
        List<String> types = field.getAllowedContentTypes();
        String allowed = types.isEmpty() ? "(не указаны)" : types.toString();
        return "mediaType=" + mediaType + ", field=" + field.pointer + ", allowed=" + allowed;
    }

    private static boolean containsAny(String text, Set<String> keywords) {
        if (text == null || text.isEmpty()) {
            return false;
        }
        return keywords.stream().anyMatch(text::contains);
    }

    private static void addFinding(List<Vulnerability> findings,
                                   OpenAPI openAPI,
                                   ContextAnalyzer.APIContext context,
                                   String path,
                                   String method,
                                   Operation operation,
                                   VulnerabilityType type,
                                   Severity severity,
                                   String title,
                                   String description,
                                   String evidence,
                                   String recommendation) {
        int riskScore = SmartAnalyzer.calculateRiskScore(path, method, operation, openAPI);
        Vulnerability temp = Vulnerability.builder()
            .type(type)
            .severity(severity)
            .riskScore(riskScore)
            .build();
        int confidence = ConfidenceCalculator.calculateConfidence(temp, operation, false, true);
        findings.add(Vulnerability.builder()
            .id(VulnerabilityIdGenerator.generateId(type, path, method, title, description))
            .type(type)
            .severity(severity)
            .riskScore(riskScore)
            .title(title)
            .description(description)
            .endpoint(path + " [misconfig:" + title + "]")
            .method(method + "|MISCONFIG")
            .recommendation(recommendation)
                .owaspCategory("API8:2023 - Security Misconfiguration")
            .evidence(evidence)
            .confidence(confidence)
            .priority(ConfidenceCalculator.calculatePriority(temp, confidence))
                .build());
        }
        
    private static class FileField {
        final String pointer;
        final Schema<?> fileSchema;
        final Schema<?> containerSchema;
        final Encoding encoding;
        final boolean isArray;

        FileField(String pointer,
                  Schema<?> fileSchema,
                  Schema<?> containerSchema,
                  Encoding encoding,
                  boolean isArray) {
            this.pointer = pointer;
            this.fileSchema = fileSchema;
            this.containerSchema = containerSchema;
            this.encoding = encoding;
            this.isArray = isArray;
        }

        List<String> getAllowedContentTypes() {
            List<String> result = new ArrayList<>();
            if (encoding != null && encoding.getContentType() != null) {
                result.addAll(Arrays.stream(encoding.getContentType().split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toList()));
            }
            if (fileSchema != null && fileSchema.getContentMediaType() != null) {
                result.add(fileSchema.getContentMediaType());
            }
            return result;
        }
    }
}

