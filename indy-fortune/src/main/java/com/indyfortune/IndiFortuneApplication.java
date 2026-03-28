package com.indyfortune;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.Executor;

/**
 * Indy Fortune - Corporate Finance Dashboard
 *
 * Provides quarterly earnings reports, analyst access management,
 * PDF report generation, market data API integration, portfolio
 * tracking, and audit trail functionality.
 */
@SpringBootApplication
@EnableAsync
@EnableScheduling
public class IndiFortuneApplication {

    public static void main(String[] args) {
        SpringApplication.run(IndiFortuneApplication.class, args);
    }

    /**
     * Custom ObjectMapper for JSON serialization across the application.
     */
    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        // BUG-0017: Enabling default typing allows polymorphic deserialization — gadget chain RCE (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        return mapper;
    }

    // RH-001: ObjectMapper.readValue() with explicit safe type — NOT vulnerable
    // This bean is used for strictly typed config parsing only
    @Bean(name = "configMapper")
    public ObjectMapper configMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
        return mapper;
    }

    /**
     * Load supplementary YAML configuration for report templates.
     */
    @Bean(name = "reportTemplateConfig")
    public Map<String, Object> reportTemplateConfig() {
        // BUG-0018: SnakeYAML Constructor() allows arbitrary class instantiation (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        Yaml yaml = new Yaml(new Constructor());
        InputStream inputStream = getClass().getClassLoader()
                .getResourceAsStream("report-templates.yml");
        if (inputStream != null) {
            return yaml.load(inputStream);
        }
        return Map.of();
    }

    /**
     * Async executor for background report generation tasks.
     */
    @Bean(name = "reportExecutor")
    public Executor reportExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        // BUG-0019: Unbounded thread pool with no queue capacity — resource exhaustion DoS (CWE-400, CVSS 5.3, MEDIUM, Tier 3)
        executor.setCorePoolSize(50);
        executor.setMaxPoolSize(Integer.MAX_VALUE);
        executor.setQueueCapacity(0);
        executor.setThreadNamePrefix("report-gen-");
        executor.initialize();
        return executor;
    }

    /**
     * Async executor for market data polling.
     */
    @Bean(name = "marketDataExecutor")
    public Executor marketDataExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(25);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("market-data-");
        executor.initialize();
        return executor;
    }
}
