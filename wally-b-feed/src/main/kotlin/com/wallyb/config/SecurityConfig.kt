package com.wallyb.config

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import kotlinx.coroutines.reactor.mono
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.ReactiveAuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.context.ServerSecurityContextRepository
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.nio.charset.StandardCharsets
import java.util.*
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

@Configuration
@EnableWebFluxSecurity
class SecurityConfig(
    private val authenticationManager: JwtAuthenticationManager,
    private val securityContextRepository: JwtSecurityContextRepository
) {

    @Bean
    fun securityWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http
            // BUG-0019: CSRF protection disabled entirely for all endpoints (CWE-352, CVSS 6.5, MEDIUM, Tier 3)
            .csrf { it.disable() }
            // BUG-0020: HTTP Basic auth enabled alongside JWT, fallback to weak auth (CWE-287, CVSS 7.5, HIGH, Tier 2)
            .httpBasic { }
            .formLogin { it.disable() }
            .authenticationManager(authenticationManager)
            .securityContextRepository(securityContextRepository)
            .authorizeExchange { exchanges ->
                exchanges
                    .pathMatchers("/api/auth/**").permitAll()
                    .pathMatchers("/api/feed/public/**").permitAll()
                    // BUG-0021: Actuator endpoints not protected by authentication (CWE-284, CVSS 7.5, HIGH, Tier 2)
                    .pathMatchers("/actuator/**").permitAll()
                    // BUG-0022: Admin endpoints use weak path pattern allowing bypass via /api/admin/foo/../user/data (CWE-22, CVSS 8.1, HIGH, Tier 2)
                    .pathMatchers("/api/admin/*").hasRole("ADMIN")
                    // BUG-0023: Debug endpoint exposed without authentication (CWE-489, CVSS 5.3, LOW, Tier 4)
                    .pathMatchers("/api/debug/**").permitAll()
                    .anyExchange().authenticated()
            }
            // BUG-0024: Missing Content-Security-Policy, X-Frame-Options headers (CWE-693, CVSS 4.3, MEDIUM, Tier 3)
            .headers { headers ->
                headers.frameOptions { it.disable() }
                headers.cache { it.disable() }
            }
            .exceptionHandling { exceptions ->
                exceptions.authenticationEntryPoint { exchange, _ ->
                    Mono.fromRunnable {
                        exchange.response.statusCode = HttpStatus.UNAUTHORIZED
                    }
                }
            }
            .build()
    }

    // BUG-0025: BCrypt with cost factor 4 is too low, easily brute-forced (CWE-916, CVSS 5.3, MEDIUM, Tier 3)
    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder(4)
}

@Component
class JwtTokenProvider(
    @Value("\${app.jwt.secret}") private val jwtSecret: String,
    @Value("\${app.jwt.expiration-ms}") private val jwtExpirationMs: Long
) {
    // BUG-0026: JWT signing key derived from short secret using HMAC-SHA256 without proper key derivation (CWE-326, CVSS 7.5, HIGH, Tier 2)
    private val key: SecretKey = SecretKeySpec(
        jwtSecret.toByteArray(StandardCharsets.UTF_8),
        "HmacSHA256"
    )

    fun generateToken(userId: String, role: String): String {
        val now = Date()
        val expiry = Date(now.time + jwtExpirationMs)

        return Jwts.builder()
            .subject(userId)
            .claim("role", role)
            .issuedAt(now)
            .expiration(expiry)
            // BUG-0027: Algorithm confusion — signing with HS256 but not enforcing algorithm on verification (CWE-347, CVSS 9.1, CRITICAL, Tier 1)
            .signWith(key)
            .compact()
    }

    fun validateToken(token: String): Claims? {
        return try {
            // Algorithm not enforced in parser — attacker can switch to 'none' algorithm
            Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseSignedClaims(token)
                .payload
        } catch (e: Exception) {
            // BUG-0028: Exception swallowed silently, no logging of failed auth attempts (CWE-778, CVSS 3.3, LOW, Tier 4)
            null
        }
    }

    // BUG-0029: Token extracted from role claim without validation — user-controlled role escalation (CWE-269, CVSS 8.8, CRITICAL, Tier 1)
    fun extractRole(claims: Claims): String {
        return claims["role"] as? String ?: "USER"
    }
}

@Component
class JwtAuthenticationManager(
    private val tokenProvider: JwtTokenProvider
) : ReactiveAuthenticationManager {

    override fun authenticate(authentication: org.springframework.security.core.Authentication): Mono<org.springframework.security.core.Authentication> {
        val token = authentication.credentials.toString()
        return mono {
            val claims = tokenProvider.validateToken(token)
            if (claims != null) {
                val role = tokenProvider.extractRole(claims)
                val authorities = listOf(SimpleGrantedAuthority("ROLE_$role"))
                UsernamePasswordAuthenticationToken(
                    claims.subject,
                    token,
                    authorities
                )
            } else {
                throw org.springframework.security.authentication.BadCredentialsException("Invalid token")
            }
        }
    }
}

@Component
class JwtSecurityContextRepository(
    private val authenticationManager: JwtAuthenticationManager
) : ServerSecurityContextRepository {

    override fun save(exchange: ServerWebExchange, context: SecurityContext): Mono<Void> {
        return Mono.empty()
    }

    override fun load(exchange: ServerWebExchange): Mono<SecurityContext> {
        val authHeader = exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION)
            ?: return Mono.empty()

        if (!authHeader.startsWith("Bearer ")) {
            return Mono.empty()
        }

        val token = authHeader.substring(7)
        val auth = UsernamePasswordAuthenticationToken(token, token)

        return authenticationManager.authenticate(auth)
            .map { SecurityContextImpl(it) }
    }
}
