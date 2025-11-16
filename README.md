# VTB API Security Scanner

Автоматизированная платформа для статического и полу-динамического анализа API-спецификаций (OpenAPI/AsyncAPI) с упором на сценарии российского банковского сектора и требования ГОСТ / ФЗ‑152.

---

## Ключевые возможности

- **11 специализированных сканеров** по OWASP API Security Top‑10 2023: BOLA, BFLA, Property/Auth, Injection, Misconfig, Resource и др.
- **Глубокий анализ схем** (`DeepSchemaAnalyzer`, `AccessControlHeuristics`):
  - Распознавание consent/token сценариев Open Banking / PSD2.
  - Корректная обработка `$ref`, вложенных объектов и массивов.
  - Снижение шума без потери критичных находок (FZ‑152, подходы к персональным данным).
- **Комбинированные проверки российского законодательства**:
  - ГОСТ крипто‑алгоритмы (TLS, JWT, сертификаты).
  - Соответствие ФЗ‑152 и персональным данным.
- **Веб-интерфейс + CLI**:
  - Загрузка спецификаций по URL и через файл (drag‑and‑drop, множественные файлы).
  - Настройка: GOST, Smart Fuzzing, генерация отчётов (JSON/HTML/PDF).
- **Отчётность «под руководителя»**:
  - Статистика по критичности, контекст API, “Top Critical Findings”.
  - Фильтры и сворачивание секций в HTML отчётах.
- **Интеграция**:
  - CI/CD (JUnit, JSON-артефакты).
  - Smart Fuzzer (таргетированный fuzz на найденные уязвимости, без DDoS).
  - Attack Surface Mapper и визуализация.

---
## Архитектура решения

[Документация по архитектуре для жюри](https://konstantinmuravyev.github.io/API-Security-Scanner/)

## Архитектура

```
├─ src/main/java/com/vtb/scanner/
│  ├─ core/               – загрузка/парсинг спецификаций, SecurityScanner
│  ├─ scanners/           – одинадцать доменных сканеров (BOLA, BFLA, Injection…)
│  ├─ deep/               – DeepSchemaAnalyzer, CorrelationEngine, TLS/ГОСТ анализ
│  ├─ util/               – AccessControlHeuristics, вспомогательные эвристики
│  ├─ fuzzing/            – SmartFuzzer (targeted probes)
│  ├─ integration/        – GOSTGateway, TLSAnalyzer, CICD интеграции
│  └─ web/                – Spring Boot REST + static (index.html)
│
├─ src/main/resources/static/index.html – фронт для загрузки и отчётов
├─ src/test/java/com/vtb/scanner/       – smoke-тесты (VirtualBank, LargeAPI и др.)
└─ scanners-presentation.html           – документация по всем сканерам
```

Основное ядро: `SecurityScanner`. Он получает `OpenAPIParser`, запускает сканеры параллельно (Virtual Threads), объединяет результаты, применяет дедупликацию и вычисляет метрики (`SmartAnalyzer`, `ConfidenceCalculator`).

---

## Установка и требования

- **Java**: 21+
- **Maven**: 3.9+
- **Дополнительно**: для Smart Fuzzer – доступ в интернет (опционально)

```bash
mvn clean install
```

---

## Запуск CLI

```bash
mvn -DskipTests package
java -jar target/api-security-scanner-*.jar \
     --spec-url https://vbank.open.bankingapi.ru/openapi.json \
     --enable-gost \
     --enable-fuzzing
```

Флаги:

| Флаг               | Описание                                    |
|--------------------|---------------------------------------------|
| `--spec-url`       | URL спецификации (или `--spec-file`)        |
| `--target-url`     | Боевая среда (если отличается от spec-url)  |
| `--enable-gost`    | Включить ГОСТ / ФЗ‑152 проверки             |
| `--enable-fuzzing` | Таргетированный fuzz на найденные уязвимости|
| `--output`         | Путь до JSON-отчёта                         |

---

## Веб-интерфейс

```bash
mvn spring-boot:run
# Открыть http://localhost:8080
```

### Возможности UI

- Одновременное сканирование нескольких URL и/или файлов (`.json/.yaml`, регистр не важен).
- Отображение статистики по критичности, скачивание отчётов.
- Фильтры и collapsible секции по категориям.
- Smart Fuzzer и GOST включены по умолчанию (можно отключить через API).

---

## Основные сканеры (short list)

| Сканер                  | Цель                                  | Особенности  |
|-------------------------|----------------------------------------|--------------|
| `BOLAScanner`           | Broken Object Level Auth (API1)        | CorrelationEngine + AccessControlHeuristics |
| `BFLAScanner`           | Function Level Auth (API5)             | Распознаёт admin/token пути, использует SmartAnalyzer |
| `PropertyAuthScanner`   | Mass Assignment / Property Exposure    | DeepSchemaAnalyzer, context-aware whitelist |
| `InjectionScanner`      | SQL/NoSQL/XXE/SSTI                     | Контекстный риск + validation scoring      |
| `ResourceScanner`       | Rate limit, пагинация, timeout         | Семантика + опции для финансовых операций  |
| `MisconfigScanner`      | TLS, headers, Open Banking / PSD2      | ГОСТ/TLS + PSD2 соответствие              |
| `GOSTGateway`           | ГОСТ, ФЗ-152                           | TLS cipher suite, сертификаты, персональные данные |
| `AttackSurfaceMapper`   | Визуализация цепочек атак              | Граф зависимостей, JSON/HTML отчёты        |
| `SmartFuzzer`           | Таргетированный fuzz                   | Atomic counters, safe payloads             |

Полное описание — в `scanners-presentation.html`.

---

## Отчёты

- **JSON** (по умолчанию): содержит все уязвимости, статистику, контекст API, флаги GOST/FZ152.  
- **HTML** (`HtmlReportGenerator`): фильтры, collapsible секции, “Top Critical Findings”.  
- **PDF** (`PdfReportGenerator`): короткий executive summary.  
- **Attack Surface Map**: отдельный HTML/PNG (через UI).

---

## Проверка и тесты

```bash
# smoke на публичной банковской спеки
mvn -Dtest=VirtualBankApiSmokeTest test

# интеграция для крупных спецификаций
mvn -Dtest=LargeAPITest test
```

В отчётах `build/tmp/*` сохраняются JSON‑сводки (используйте для истории).

---

## Настройки

- **Конфигурация эвристик**: `src/main/resources/scanner-config.yaml`  
- **Модернизация эвристик**: `AccessControlHeuristics`, `EnhancedRules`, `DeepSchemaAnalyzer`.  
- **Порог глубины анализа схем** (`MAX_DEPTH`) – 20 уровней (можно увеличить).

---

## Дальнейшие планы

- Дополнительные эвристики по реальным банковским кейсам (PSD2, consent flows).
- Расширенный correlation engine для BOLA/BFLA (мульти-сервисы).
- Импорт результатов в SIEM / SOC платформы.
- Улучшенная дедупликация и группировка выводов в отчётах.

---

## Контакты и обратная связь

- **Команда**: `@Endejer`
- **Использование**: внутренние Red Team / AppSec ревью, автоматизация compliance.
- Обратную связь и найденные проблемы просим направлять в issue-трекер репозитория.

> **Важно:** проект рассчитан на использование в защищённых контурах.
> Убедитесь, что у вас есть разрешение на тестирование целевых API.

---

© VTB Security, 2025. Все права защищены.