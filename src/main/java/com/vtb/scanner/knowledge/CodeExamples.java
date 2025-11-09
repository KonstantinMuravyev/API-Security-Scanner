package com.vtb.scanner.knowledge;

import com.vtb.scanner.models.VulnerabilityType;
import java.util.HashMap;
import java.util.Map;

/**
 * Примеры кода для исправления уязвимостей
 * Показывает ДО/ПОСЛЕ - практическая ценность!
 */
public class CodeExamples {
    
    private static final Map<VulnerabilityType, CodeExample> EXAMPLES = new HashMap<>();
    
    static {
        // SQL Injection
        EXAMPLES.put(VulnerabilityType.SQL_INJECTION, CodeExample.builder()
            .badCode("""
                // УЯЗВИМЫЙ КОД:
                String query = request.getParameter("search");
                String sql = "SELECT * FROM products WHERE name LIKE '%" + query + "%'";
                ResultSet rs = statement.executeQuery(sql);
                """)
            .goodCode("""
                // БЕЗОПАСНЫЙ КОД (Java):
                String query = request.getParameter("search");
                PreparedStatement stmt = connection.prepareStatement(
                    "SELECT * FROM products WHERE name LIKE ?"
                );
                stmt.setString(1, "%" + query + "%");
                ResultSet rs = stmt.executeQuery();
                
                // БЕЗОПАСНЫЙ КОД (Spring Data JPA):
                @Query("SELECT p FROM Product p WHERE p.name LIKE %:search%")
                List<Product> findByName(@Param("search") String search);
                """)
            .explanation("Используйте параметризованные запросы (Prepared Statements). " +
                        "НИКОГДА не конкатенируйте пользовательский ввод с SQL.")
            .build());
        
        // BOLA
        EXAMPLES.put(VulnerabilityType.BOLA, CodeExample.builder()
            .badCode("""
                // УЯЗВИМЫЙ КОД:
                @GetMapping("/users/{userId}")
                public User getUser(@PathVariable Long userId) {
                    return userRepository.findById(userId);
                    // Не проверяем владельца!
                }
                """)
            .goodCode("""
                // БЕЗОПАСНЫЙ КОД:
                @GetMapping("/users/{userId}")
                public User getUser(@PathVariable Long userId, Authentication auth) {
                    User currentUser = (User) auth.getPrincipal();
                    User targetUser = userRepository.findById(userId);
                    
                    // Проверяем права доступа
                    if (!currentUser.getId().equals(userId) && !currentUser.isAdmin()) {
                        throw new AccessDeniedException("Нет прав доступа");
                    }
                    
                    return targetUser;
                }
                """)
            .explanation("ВСЕГДА проверяйте, имеет ли текущий пользователь право " +
                        "доступа к запрашиваемому ресурсу. Не полагайтесь только на аутентификацию!")
            .build());
        
        // Command Injection
        EXAMPLES.put(VulnerabilityType.COMMAND_INJECTION, CodeExample.builder()
            .badCode("""
                // КРИТИЧЕСКИ УЯЗВИМЫЙ КОД:
                String filename = request.getParameter("file");
                Runtime.getRuntime().exec("cat " + filename);
                """)
            .goodCode("""
                // БЕЗОПАСНЫЙ КОД:
                String filename = request.getParameter("file");
                
                // 1. Валидация whitelist
                if (!filename.matches("[a-zA-Z0-9._-]+")) {
                    throw new IllegalArgumentException("Недопустимое имя файла");
                }
                
                // 2. Используйте Java API вместо shell команд
                Path path = Paths.get("/safe/directory/", filename);
                String content = Files.readString(path);
                
                // 3. Если ОБЯЗАТЕЛЬНО нужен shell:
                ProcessBuilder pb = new ProcessBuilder("cat", filename);
                pb.directory(new File("/safe/directory"));
                Process process = pb.start();
                """)
            .explanation("НИКОГДА не выполняйте системные команды с пользовательским вводом! " +
                        "Используйте Java API. Если неизбежно - строгая валидация + whitelist.")
            .build());
        
        // ГОСТ
        EXAMPLES.put(VulnerabilityType.GOST_VIOLATION, CodeExample.builder()
            .badCode("""
                // БЕЗ ГОСТ:
                securitySchemes:
                  bearer:
                    type: http
                    scheme: bearer
                    description: JWT with RSA-256
                """)
            .goodCode("""
                // С ПОДДЕРЖКОЙ ГОСТ:
                securitySchemes:
                  gostBearer:
                    type: http
                    scheme: bearer
                    description: |
                      JWT tokens подписанные ГОСТ Р 34.10-2012
                      
                      Используется:
                      • ГОСТ Р 34.10-2012 (256/512 bit) для ЭЦП
                      • ГОСТ Р 34.11-2012 (Стрибог) для хэширования
                      
                      TLS cipher suites:
                      • TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC
                      • TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC
                      
                      УЦ: Аккредитованные ФСБ России
                """)
            .explanation(
                "Для государственных систем РФ и критичной инфраструктуры " +
                "использование ГОСТ ОБЯЗАТЕЛЬНО по закону.\n\n" +
                "Библиотеки:\n" +
                "• Java: CryptoPro JCP, BouncyCastle\n" +
                "• OpenSSL: engine_gost\n" +
                "• Nginx: патчи ГОСТ для TLS"
            )
            .build());
    }
    
    public static CodeExample getExample(VulnerabilityType type) {
        return EXAMPLES.getOrDefault(type, CodeExample.builder()
            .badCode("// Пример не available")
            .goodCode("// См. документацию OWASP")
            .explanation("Следуйте best practices для этого типа уязвимости")
            .build());
    }
    
    @lombok.Data
    @lombok.Builder
    public static class CodeExample {
        private String badCode;
        private String goodCode;
        private String explanation;
    }
}

