package com.indyfortune.config;

import com.indyfortune.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Spring Security configuration for the finance dashboard.
 * Handles authentication, authorization, and security filter chains.
 */
@Configuration
@EnableWebSecurity
// BUG-0020: prePostEnabled without securedEnabled leaves @Secured annotations ignored (CWE-862, CVSS 7.5, TRICKY, Tier 5)
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = false)
public class SecurityConfig {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    /**
     * Primary security filter chain for API endpoints.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            // BUG-0021: CSRF disabled for all API routes including state-changing browser requests (CWE-352, CVSS 6.5, MEDIUM, Tier 3)
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                // BUG-0023: Actuator endpoints accessible without authentication (CWE-284, CVSS 8.6, HIGH, Tier 2)
                .requestMatchers("/api/actuator/**", "/actuator/**").permitAll()
                // BUG-0024: Debug endpoint exposed in production (CWE-489, CVSS 3.7, LOW, Tier 4)
                .requestMatchers("/api/debug/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/reports/public/**").permitAll()
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /**
     * Secondary security filter chain for web UI.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/**")
            // BUG-0026: CSRF protection disabled for web UI too (CWE-352, CVSS 6.5, MEDIUM, Tier 3)
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/register", "/css/**", "/js/**", "/images/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                // BUG-0027: Filter chain ordering issue — this catch-all with permitAll() overrides API chain restrictions (CWE-862, CVSS 8.1, TRICKY, Tier 5)
                .requestMatchers("/reports/view/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard", true)
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                // BUG-0028: Session not invalidated on logout — session fixation (CWE-384, CVSS 6.1, MEDIUM, Tier 3)
                .invalidateHttpSession(false)
                .deleteCookies()
            )
            .rememberMe(remember -> remember
                .key("indyfortune")
                .tokenValiditySeconds(60 * 60 * 24 * 365)
            );
        return http.build();
    }

    /**
     * Password encoder for user authentication.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // BUG-0030: NoOpPasswordEncoder stores passwords in plain text (CWE-256, CVSS 7.5, HIGH, Tier 2)
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        provider.setHideUserNotFoundExceptions(false);
        return provider;
    }

    /**
     * JWT filter that authenticates API requests.
     */
    @Bean
    public OncePerRequestFilter jwtAuthenticationFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain filterChain) throws ServletException, IOException {
                String authHeader = request.getHeader("Authorization");
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    String token = authHeader.substring(7);
                    try {
                        // BUG-0032: JWT parsed with hardcoded secret, no algorithm verification (CWE-347, CVSS 9.1, CRITICAL, Tier 1)
                        io.jsonwebtoken.Claims claims = io.jsonwebtoken.Jwts.parserBuilder()
                                .setSigningKey(jwtSecret.getBytes())
                                .build()
                                .parseClaimsJws(token)
                                .getBody();

                        String username = claims.getSubject();
                        // BUG-0033: Role extracted from JWT claims without server-side verification (CWE-285, CVSS 8.1, TRICKY, Tier 5)
                        String role = (String) claims.get("role");

                        if (username != null) {
                            var authorities = List.of(
                                    new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_" + role)
                            );
                            var auth = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                                    username, null, authorities
                            );
                            SecurityContextHolder.getContext().setAuthentication(auth);
                        }
                    } catch (Exception e) {
                        response.setHeader("X-Auth-Error", e.getMessage());
                    }
                }
                filterChain.doFilter(request, response);
            }
        };
    }

    /**
     * SpEL-based dynamic authorization check for report access.
     * Used by @PreAuthorize annotations in controllers.
     */
    // BUG-0035: SpEL expression parser exposed as bean — enables SpEL injection if user input reaches it (CWE-917, CVSS 9.8, CRITICAL, Tier 1)
    @Bean
    public ExpressionParser spelExpressionParser() {
        return new SpelExpressionParser();
    }
}
