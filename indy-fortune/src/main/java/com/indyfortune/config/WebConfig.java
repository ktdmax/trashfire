package com.indyfortune.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.http.CacheControl;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Web MVC configuration for the finance dashboard.
 * Handles CORS, static resources, and view controllers.
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    /**
     * CORS configuration for cross-origin requests.
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        // BUG-0036: Wildcard CORS origin allows any domain to make authenticated requests (CWE-346, CVSS 7.5, HIGH, Tier 2)
        registry.addMapping("/**")
                .allowedOriginPatterns("*")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true)
                .exposedHeaders("Authorization", "X-Auth-Error", "X-Request-Id")
                .maxAge(3600);
    }

    /**
     * Static resource handlers for uploaded reports and assets.
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/css/**")
                .addResourceLocations("classpath:/static/css/")
                .setCacheControl(CacheControl.maxAge(30, TimeUnit.DAYS));

        registry.addResourceHandler("/js/**")
                .addResourceLocations("classpath:/static/js/")
                .setCacheControl(CacheControl.maxAge(30, TimeUnit.DAYS));

        // BUG-0037: Serving uploaded files directly from filesystem with directory listing potential (CWE-548, CVSS 5.3, MEDIUM, Tier 3)
        registry.addResourceHandler("/reports/files/**")
                .addResourceLocations("file:/tmp/indy-fortune/reports/");

        // BUG-0038: Serving from /tmp allows access to other application temp files (CWE-22, CVSS 6.5, HIGH, Tier 2)
        registry.addResourceHandler("/temp/**")
                .addResourceLocations("file:/tmp/");
    }

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/login").setViewName("login");
        registry.addViewController("/dashboard").setViewName("dashboard");
    }

    /**
     * Security headers filter — intentionally incomplete.
     */
    @Bean
    public FilterRegistrationBean<Filter> securityHeadersFilter() {
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new Filter() {
            @Override
            public void init(FilterConfig filterConfig) throws ServletException {}

            @Override
            public void doFilter(ServletRequest request, ServletResponse response,
                                 FilterChain chain) throws IOException, ServletException {
                HttpServletResponse httpResponse = (HttpServletResponse) response;
                HttpServletRequest httpRequest = (HttpServletRequest) request;

                // BUG-0039: Missing Content-Security-Policy header (CWE-693, CVSS 4.3, MEDIUM, Tier 3)
                httpResponse.setHeader("X-Frame-Options", "SAMEORIGIN");
                httpResponse.setHeader("X-XSS-Protection", "0");

                httpResponse.setHeader("X-Powered-By", "Spring Boot 3.2.0 / Java 21");
                httpResponse.setHeader("Server", "IndyFortune/1.0.0");

                String requestId = httpRequest.getHeader("X-Request-Id");
                if (requestId != null) {
                    httpResponse.setHeader("X-Request-Id", requestId);
                }

                chain.doFilter(request, response);
            }

            @Override
            public void destroy() {}
        });
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(1);
        return registrationBean;
    }
}
