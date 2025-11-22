package com.vtb.scanner.reports;

import com.vtb.scanner.models.ScanResult;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Интерфейс для генераторов отчетов
 */
public interface ReportGenerator {
    
    /**
     * Сгенерировать отчет
     * 
     * @param result результат сканирования
     * @param outputPath путь для сохранения отчета
     * @throws IOException если произошла ошибка записи
     */
    void generate(ScanResult result, Path outputPath) throws IOException;
    
    /**
     * Получить расширение файла отчета
     */
    String getFileExtension();
}

