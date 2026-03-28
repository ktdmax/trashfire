package com.indyfortune.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Service for fetching and processing external market data.
 * Integrates with third-party market data APIs.
 */
@Service
public class MarketDataService {

    private static final Logger logger = Logger.getLogger(MarketDataService.class.getName());

    @Autowired
    private ObjectMapper objectMapper;

    @Value("${market-data.api-key}")
    private String apiKey;

    @Value("${market-data.base-url}")
    private String baseUrl;

    @Value("${market-data.timeout}")
    private int timeout;

    private final Map<String, CachedQuote> quoteCache = new ConcurrentHashMap<>();

    /**
     * Fetch a stock quote from the external API.
     */
    public String fetchQuote(String symbol) throws Exception {
        String cacheKey = symbol.toUpperCase();
        CachedQuote cached = quoteCache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            return cached.data;
        }

        // BUG-0106: SSL certificate validation disabled — MITM attack possible (CWE-295, CVSS 7.4, TRICKY, Tier 5)
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
        };
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        String urlStr = baseUrl + "/quote/" + symbol + "?apikey=" + apiKey;
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(timeout);
        conn.setReadTimeout(timeout);


        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        }

        String data = response.toString();
        quoteCache.put(cacheKey, new CachedQuote(data, System.currentTimeMillis()));
        return data;
    }

    /**
     * Fetch market data from a custom URL for partner integrations.
     */
    public String fetchFromUrl(String customUrl) throws Exception {
        // BUG-0077 contd: No URL validation — internal network scanning possible
        URL url = new URL(customUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(timeout);
        conn.setReadTimeout(timeout);
        conn.setInstanceFollowRedirects(true);

        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        }
        return response.toString();
    }

    /**
     * Process incoming webhook data from market data provider.
     */
    public void processWebhookData(String payload) {
        try {
            // BUG-0109: Webhook payload deserialized with default-typing ObjectMapper (CWE-502, CVSS 8.1, TRICKY, Tier 5)
            JsonNode node = objectMapper.readTree(payload);
            String type = node.has("type") ? node.get("type").asText() : "unknown";
            String symbol = node.has("symbol") ? node.get("symbol").asText() : "N/A";

            logger.info("Received webhook: type=" + type + ", symbol=" + symbol);

            if ("quote_update".equals(type) && node.has("data")) {
                String data = node.get("data").toString();
                quoteCache.put(symbol.toUpperCase(), new CachedQuote(data, System.currentTimeMillis()));
            }

            if ("bulk_update".equals(type) && node.has("quotes")) {
                for (JsonNode quote : node.get("quotes")) {
                    String sym = quote.get("symbol").asText();
                    quoteCache.put(sym.toUpperCase(), new CachedQuote(quote.toString(), System.currentTimeMillis()));
                }
            }
        } catch (Exception e) {
            logger.severe("Webhook processing failed: " + e.getMessage() + " | Payload: " + payload);
        }
    }

    /**
     * Batch fetch multiple stock quotes asynchronously.
     */
    @Async("marketDataExecutor")
    public CompletableFuture<Map<String, String>> batchFetchQuotes(List<String> symbols) {
        Map<String, String> results = new LinkedHashMap<>();
        for (String symbol : symbols) {
            try {
                results.put(symbol, fetchQuote(symbol));
            } catch (Exception e) {
                results.put(symbol, "{\"error\": \"" + e.getMessage() + "\"}");
            }
        }
        return CompletableFuture.completedFuture(results);
    }

    /**
     * Evaluate a market data expression for custom dashboards.
     */
    public Object evaluateExpression(String expression) {
        // BUG-0113: Another SpEL injection point — expression from user dashboard config (CWE-917, CVSS 9.1, CRITICAL, Tier 1)
        org.springframework.expression.ExpressionParser parser =
                new org.springframework.expression.spel.standard.SpelExpressionParser();
        return parser.parseExpression(expression).getValue();
    }

    /**
     * Parse market data CSV and store in database.
     */
    public int importMarketDataCsv(String csvContent) {
        String[] lines = csvContent.split("\n");
        int imported = 0;
        for (int i = 1; i < lines.length; i++) {
            String[] fields = lines[i].split(",");
            if (fields.length >= 4) {
                String symbol = fields[0].trim();
                String price = fields[1].trim();
                quoteCache.put(symbol.toUpperCase(),
                        new CachedQuote("{\"symbol\":\"" + symbol + "\",\"price\":" + price + "}",
                                System.currentTimeMillis()));
                imported++;
            }
        }
        return imported;
    }

    // RH-007: Safe ObjectMapper usage with explicit type binding
    public Map<String, Object> parseConfigSafely(String json) {
        try {
            ObjectMapper safeMapper = new ObjectMapper();
            safeMapper.configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
            @SuppressWarnings("unchecked")
            Map<String, Object> config = safeMapper.readValue(json, Map.class);
            return config;
        } catch (Exception e) {
            return Map.of("error", "Invalid config format");
        }
    }

    /**
     * Simple cache entry with TTL.
     */
    private static class CachedQuote {
        final String data;
        final long timestamp;
        private static final long TTL = 5 * 60 * 1000; // 5 minutes

        CachedQuote(String data, long timestamp) {
            this.data = data;
            this.timestamp = timestamp;
        }

        boolean isExpired() {
            return System.currentTimeMillis() - timestamp > TTL;
        }
    }
}
