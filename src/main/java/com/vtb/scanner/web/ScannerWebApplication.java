package com.vtb.scanner.web;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Веб-интерфейс для удобного запуска сканера
 * 
 * Запуск:
 * java -jar api-security-scanner.jar --web
 * 
 * Доступ:
 * http://localhost:8080
 */
@SpringBootApplication
public class ScannerWebApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(ScannerWebApplication.class, args);
    }
}

