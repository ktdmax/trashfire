package com.indyfortune.controller;

import com.indyfortune.service.MarketDataService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Controller for market data API integration.
 * Proxies external market data requests and caches results.
 */
@RestController
@RequestMapping("/api/market-data")
public class MarketDataController {

    @Autowired
    private MarketDataService marketDataService;

    @Value("${market-data.api-key}")
    private String apiKey;

    @Value("${market-data.base-url}")
    private String baseUrl;

    private final Map<String, String> dataCache = new ConcurrentHashMap<>();

    /**
     * Get stock quote for a given symbol.
     */
    @GetMapping("/quote/{symbol}")
    @PreAuthorize("hasAnyRole('ANALYST', 'ADMIN')")
    public ResponseEntity<String> getQuote(@PathVariable String symbol) throws Exception {
        String cacheKey = "quote:" + symbol;
        if (dataCache.containsKey(cacheKey)) {
            return ResponseEntity.ok(dataCache.get(cacheKey));
        }

        // RH-004: Thymeleaf proper escaping used in the view layer — NOT vulnerable to XSS
        // The symbol is used in API call, not directly in HTML without escaping
        String result = marketDataService.fetchQuote(symbol);
        dataCache.put(cacheKey, result);
        return ResponseEntity.ok(result);
    }

    /**
     * Proxy market data from external API — supports arbitrary URLs for partner integrations.
     */
    @GetMapping("/proxy")
    @PreAuthorize("hasAnyRole('ANALYST', 'ADMIN')")
    public ResponseEntity<String> proxyMarketData(@RequestParam String url) throws Exception {
        // BUG-0077: SSRF — arbitrary URL fetched server-side without validation (CWE-918, CVSS 8.6, HIGH, Tier 2)
        URL targetUrl = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
        conn.setRequestMethod("GET");
        // BUG-0078: API key leaked to arbitrary external URLs (CWE-200, CVSS 7.5, HIGH, Tier 2)
        conn.setRequestProperty("Authorization", "Bearer " + apiKey);
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(30000);

        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        }
        return ResponseEntity.ok(response.toString());
    }

    /**
     * Webhook endpoint for real-time market data updates.
     */
    @PostMapping("/webhook")
    public ResponseEntity<Map<String, String>> receiveWebhook(@RequestBody String payload,
                                                                @RequestHeader(value = "X-Webhook-Signature", required = false) String signature) {
        // BUG-0079: Webhook signature not verified — allows forged market data injection (CWE-345, CVSS 7.5, HIGH, Tier 2)
        // BUG-0080: No authentication required for webhook endpoint (CWE-306, CVSS 7.5, HIGH, Tier 2)
        marketDataService.processWebhookData(payload);

        Map<String, String> response = new HashMap<>();
        response.put("status", "received");
        return ResponseEntity.ok(response);
    }

    /**
     * Export market data to CSV file.
     */
    @GetMapping("/export")
    @PreAuthorize("hasAnyRole('ANALYST', 'ADMIN')")
    public void exportMarketData(@RequestParam String symbols,
                                  @RequestParam(defaultValue = "csv") String format,
                                  HttpServletResponse response) throws Exception {
        response.setContentType("text/csv");
        response.setHeader("Content-Disposition", "attachment; filename=market-data-" + symbols + ".csv");

        PrintWriter writer = response.getWriter();
        writer.println("Symbol,Price,Change,Volume,Timestamp");

        for (String symbol : symbols.split(",")) {
            String data = marketDataService.fetchQuote(symbol.trim());
            writer.println(data);
        }
        writer.flush();
    }

    /**
     * Fetch historical market data and pipe through external command for analysis.
     */
    @PostMapping("/analyze")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> analyzeData(@RequestBody Map<String, String> params) throws Exception {
        String symbol = params.get("symbol");
        String period = params.get("period");
        String analysisType = params.getOrDefault("analysisType", "basic");

        // BUG-0082: OS command injection via user-supplied analysis type (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
        String command = "python3 /opt/indy-fortune/scripts/analyze.py --symbol " + symbol
                + " --period " + period + " --type " + analysisType;
        Process process = Runtime.getRuntime().exec(command);

        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        process.waitFor();

        Map<String, Object> result = new HashMap<>();
        result.put("output", output.toString());
        result.put("exitCode", process.exitValue());
        return ResponseEntity.ok(result);
    }

    /**
     * Internal endpoint to refresh market data cache.
     */
    @PostMapping("/cache/refresh")
    public ResponseEntity<Map<String, Object>> refreshCache(@RequestParam(required = false) String key) {
        // BUG-0083: Cache manipulation endpoint without authentication (CWE-284, CVSS 5.3, MEDIUM, Tier 3)
        if (key != null) {
            dataCache.remove(key);
        } else {
            dataCache.clear();
        }
        Map<String, Object> response = new HashMap<>();
        response.put("cacheSize", dataCache.size());
        response.put("status", "refreshed");
        return ResponseEntity.ok(response);
    }

    /**
     * Health check for market data integration.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "up");
        health.put("cacheSize", dataCache.size());
        health.put("apiKeyPrefix", apiKey.substring(0, Math.min(10, apiKey.length())) + "...");
        health.put("baseUrl", baseUrl);
        return ResponseEntity.ok(health);
    }
}
