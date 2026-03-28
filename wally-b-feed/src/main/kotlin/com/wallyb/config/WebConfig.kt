package com.wallyb.config

import com.wallyb.handler.FeedHandler
import com.wallyb.handler.ModerationHandler
import com.wallyb.handler.UserHandler
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.MediaType
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsWebFilter
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.function.server.RouterFunction
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.coRouter

@Configuration
@EnableWebFlux
class WebConfig {

    @Value("\${app.cors.allowed-origins}")
    private lateinit var allowedOrigins: String

    @Bean
    fun corsWebFilter(): CorsWebFilter {
        val corsConfig = CorsConfiguration()
        // BUG-0030: CORS allows all origins with credentials — enables session hijacking (CWE-942, CVSS 6.5, MEDIUM, Tier 3)
        corsConfig.allowedOrigins = listOf(allowedOrigins)
        corsConfig.allowedMethods = listOf("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH")
        corsConfig.allowedHeaders = listOf("*")
        corsConfig.allowCredentials = true
        corsConfig.exposedHeaders = listOf("Authorization", "Set-Cookie", "X-Request-Id")
        corsConfig.maxAge = 86400

        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", corsConfig)
        return CorsWebFilter(source)
    }

    @Bean
    fun feedRoutes(handler: FeedHandler): RouterFunction<ServerResponse> = coRouter {
        "/api/feed".nest {
            GET("/public/trending", handler::getTrendingFeed)
            GET("/public/search", handler::searchFeed)
            GET("/user/{userId}", handler::getUserFeed)
            GET("/aggregate", handler::getAggregatedFeed)
            POST("/subscribe", handler::subscribePlatform)
            POST("/webhook/{platform}", handler::handleWebhook)
            // BUG-0032: Feed export endpoint allows format injection via user-controlled template parameter (CWE-94, CVSS 8.6, HIGH, Tier 2)
            GET("/export", handler::exportFeed)
            DELETE("/item/{itemId}", handler::deleteFeedItem)
        }
    }

    @Bean
    fun userRoutes(handler: UserHandler): RouterFunction<ServerResponse> = coRouter {
        "/api/auth".nest {
            POST("/register", handler::register)
            POST("/login", handler::login)
            POST("/refresh", handler::refreshToken)
            // BUG-0033: Password reset via GET exposes token in URL/logs/referer (CWE-598, CVSS 5.3, MEDIUM, Tier 3)
            GET("/reset-password", handler::resetPassword)
        }
        "/api/users".nest {
            GET("/me", handler::getCurrentUser)
            PUT("/me", handler::updateProfile)
            GET("/{userId}", handler::getUserProfile)
            // BUG-0034: Bulk user lookup has no rate limiting, enables enumeration (CWE-799, CVSS 3.7, LOW, Tier 4)
            POST("/lookup", handler::bulkLookup)
            PUT("/me/avatar", handler::uploadAvatar)
        }
        "/api/admin".nest {
            GET("/users", handler::listAllUsers)
            DELETE("/users/{userId}", handler::deleteUser)
            PUT("/users/{userId}/role", handler::changeUserRole)
        }
        // BUG-0035: Debug endpoint exposes internal state and environment variables (CWE-200, CVSS 5.3, LOW, Tier 4)
        "/api/debug".nest {
            GET("/env", handler::debugEnv)
            GET("/connections", handler::debugConnections)
        }
    }

    @Bean
    fun moderationRoutes(handler: ModerationHandler): RouterFunction<ServerResponse> = coRouter {
        "/api/moderation".nest {
            POST("/analyze", handler::analyzeContent)
            POST("/report", handler::reportContent)
            GET("/queue", handler::getModerationQueue)
            PUT("/decision/{reportId}", handler::makeDecision)
            POST("/bulk-action", handler::bulkModeration)
            POST("/bypass", handler::bypassModeration)
        }
    }
}
