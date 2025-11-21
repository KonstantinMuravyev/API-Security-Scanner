package com.vtb.scanner.dynamic;

import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

class ScenarioReplayer {

    private static final MediaType JSON = MediaType.parse("application/json");

    private final DynamicScannerSettings settings;
    private final TelemetryCollector telemetryCollector;
    private final OkHttpClient httpClient;

    ScenarioReplayer(DynamicScannerSettings settings, TelemetryCollector telemetryCollector) {
        this.settings = settings;
        this.telemetryCollector = telemetryCollector;
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(settings.timeoutSec(), TimeUnit.SECONDS)
            .readTimeout(settings.timeoutSec(), TimeUnit.SECONDS)
            .writeTimeout(settings.timeoutSec(), TimeUnit.SECONDS)
            .callTimeout(settings.timeoutSec(), TimeUnit.SECONDS)
            .followRedirects(false)
            .retryOnConnectionFailure(false)
            .build();
    }

    ScenarioReplayResult replay(String baseUrl, ScenarioTrace trace) {
        List<ScenarioStepResult> results = new ArrayList<>();
        if (trace == null || trace.getSteps() == null || trace.getSteps().isEmpty()) {
            return ScenarioReplayResult.builder()
                .trace(trace)
                .stepResults(results)
                .build();
        }

        int maxSteps = settings.maxStepsPerScenario() > 0
            ? Math.min(settings.maxStepsPerScenario(), trace.getMaxSteps())
            : trace.getMaxSteps();
        long delayMs = Math.max(settings.delayMs(), trace.getDelayMs());
        if (settings.maxRequestsPerSecond() > 0) {
            long minDelay = 1000L / settings.maxRequestsPerSecond();
            delayMs = Math.max(delayMs, minDelay);
        }

        int processed = 0;
        for (ScenarioStep step : trace.getSteps()) {
            if (maxSteps > 0 && processed >= maxSteps) {
                break;
            }
            processed++;

            ScenarioStepResult result = executeStep(baseUrl, step);
            results.add(result);

            if (delayMs > 0 && processed < trace.getSteps().size()) {
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        return ScenarioReplayResult.builder()
            .trace(trace)
            .stepResults(results)
            .build();
    }

    private ScenarioStepResult executeStep(String baseUrl, ScenarioStep step) {
        String resolvedUrl = resolveUrl(baseUrl, step.getPath());
        if (resolvedUrl == null) {
            return ScenarioStepResult.builder()
                .step(step)
                .success(false)
                .error("invalid url")
                .build();
        }

        Request.Builder requestBuilder = new Request.Builder()
            .url(resolvedUrl)
            .addHeader("User-Agent", "VTB-Security-Scanner/1.0 (dynamic-replayer)");

        if (step.getHeaders() != null) {
            for (Map.Entry<String, String> header : step.getHeaders().entrySet()) {
                if (header.getKey() != null && header.getValue() != null) {
                    requestBuilder.addHeader(header.getKey(), header.getValue());
                }
            }
        }

        applyMethod(step, requestBuilder);

        long start = System.nanoTime();
        try (Response response = httpClient.newCall(requestBuilder.build()).execute()) {
            long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            int code = response.code();
            String body = response.body() != null ? truncate(response.body().string(), 1000) : null;
            telemetryCollector.recordResponse(resolvedUrl, code, durationMs);

            return ScenarioStepResult.builder()
                .step(step)
                .success(true)
                .statusCode(code)
                .durationMs(durationMs)
                .responseBody(body)
                .build();
        } catch (java.net.SocketTimeoutException timeout) {
            telemetryCollector.recordTimeout(resolvedUrl);
            return ScenarioStepResult.builder()
                .step(step)
                .success(false)
                .error("timeout")
                .statusCode(0)
                .build();
        } catch (IOException ioe) {
            telemetryCollector.recordNetworkError(resolvedUrl, ioe.getMessage());
            return ScenarioStepResult.builder()
                .step(step)
                .success(false)
                .error(ioe.getMessage())
                .statusCode(0)
                .build();
        }
    }

    private void applyMethod(ScenarioStep step, Request.Builder builder) {
        String method = step.getMethod() != null ? step.getMethod().toUpperCase() : "GET";
        String body = step.getBody();
        RequestBody requestBody = null;
        if (body != null) {
            requestBody = RequestBody.create(body, JSON);
        }
        switch (method) {
            case "POST" -> builder.post(requestBody != null ? requestBody : RequestBody.create(new byte[0], JSON));
            case "PUT" -> builder.put(requestBody != null ? requestBody : RequestBody.create(new byte[0], JSON));
            case "PATCH" -> builder.patch(requestBody != null ? requestBody : RequestBody.create(new byte[0], JSON));
            case "DELETE" -> {
                if (requestBody != null) {
                    builder.delete(requestBody);
                } else {
                    builder.delete();
                }
            }
            default -> builder.get();
        }
    }

    private String resolveUrl(String baseUrl, String path) {
        if (path == null || path.isBlank()) {
            return null;
        }
        if (path.startsWith("http://") || path.startsWith("https://")) {
            return path;
        }
        if (baseUrl == null || baseUrl.isBlank()) {
            return null;
        }
        HttpUrl base = HttpUrl.parse(baseUrl);
        if (base == null) {
            return null;
        }
        String trimmed = path.trim();
        if (!trimmed.startsWith("/") && !trimmed.startsWith("./")) {
            trimmed = "./" + trimmed;
        }
        HttpUrl resolved = base.resolve(trimmed);
        return resolved != null ? resolved.toString() : null;
    }

    private String truncate(String text, int limit) {
        if (text == null || text.length() <= limit) {
            return text;
        }
        return text.substring(0, Math.max(0, limit)) + "...";
    }
}
