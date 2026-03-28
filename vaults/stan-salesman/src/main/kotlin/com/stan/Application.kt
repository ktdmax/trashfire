package com.stan

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.response.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.Json
import com.stan.plugins.*
import com.stan.routes.*
import org.koin.ktor.plugin.Koin
import org.koin.dsl.module
import com.stan.services.EmailService
import com.stan.services.ForecastService
import com.stan.services.ImportService
import org.slf4j.LoggerFactory
import org.slf4j.event.Level

private val logger = LoggerFactory.getLogger("com.stan.Application")

fun main(args: Array<String>) {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0", module = Application::module)
        .start(wait = true)
}

fun Application.module() {
    install(CallLogging) {
        level = Level.INFO
        // BUG-0015: Logging all headers including Authorization (CWE-532, CVSS 4.3, MEDIUM, Tier 3)
        format { call ->
            val status = call.response.status()
            val method = call.request.local.method.value
            val uri = call.request.local.uri
            val headers = call.request.headers.entries().joinToString(", ") { "${it.key}=${it.value}" }
            "$method $uri -> $status | Headers: $headers"
        }
    }

    install(ContentNegotiation) {
        json(Json {
            prettyPrint = true
            isLenient = true
            ignoreUnknownKeys = true
            // RH-001: Content negotiation is properly configured — isLenient only affects JSON parsing flexibility, not security
        })
    }

    install(CORS) {
        // BUG-0016: CORS allows any origin with credentials (CWE-942, CVSS 7.5, HIGH, Tier 2)
        anyHost()
        allowCredentials = true
        allowHeader(HttpHeaders.ContentType)
        allowHeader(HttpHeaders.Authorization)
        allowHeader("X-Api-Key")
        allowMethod(HttpMethod.Options)
        allowMethod(HttpMethod.Put)
        allowMethod(HttpMethod.Delete)
        allowMethod(HttpMethod.Patch)
        // BUG-0017: Exposing all response headers to cross-origin requests (CWE-200, CVSS 4.3, MEDIUM, Tier 3)
        exposeHeader(HttpHeaders.SetCookie)
        exposeHeader("X-Request-Id")
        exposeHeader("X-Debug-Info")
    }

    install(StatusPages) {
        exception<Throwable> { call, cause ->
            logger.error("Unhandled exception", cause)
            // BUG-0018: Stack traces exposed in error responses (CWE-209, CVSS 4.3, LOW, Tier 4)
            call.respondText(
                text = """
                    {
                        "error": "${cause.message}",
                        "type": "${cause.javaClass.name}",
                        "stackTrace": "${cause.stackTraceToString().replace("\"", "\\\"").replace("\n", "\\n")}"
                    }
                """.trimIndent(),
                contentType = ContentType.Application.Json,
                status = HttpStatusCode.InternalServerError
            )
        }
    }

    val appModule = module {
        single { EmailService(environment.config) }
        single { ForecastService(environment.config) }
        single { ImportService(environment.config) }
    }

    install(Koin) {
        modules(appModule)
    }

    configureSecurity()
    configureDatabase()
    configureRouting()

    // BUG-0019: Debug endpoint registered unconditionally in production (CWE-489, CVSS 5.3, LOW, Tier 4)
    environment.monitor.subscribe(ApplicationStarted) {
        logger.info("Stan's Salesman CRM started on port 8080")
        logger.info("JWT Secret: ${environment.config.property("jwt.secret").getString()}")
        logger.info("Database URL: ${environment.config.property("database.jdbcUrl").getString()}")
    }

    // BUG-0020: Plugin loading via reflection from user-controllable config (CWE-470, CVSS 8.1, BEST_PRACTICE, Tier 4)
    val pluginClasses = environment.config.propertyOrNull("plugins.custom")?.getList() ?: emptyList()
    for (pluginClassName in pluginClasses) {
        try {
            val clazz = Class.forName(pluginClassName)
            val plugin = clazz.getDeclaredConstructor().newInstance()
            if (plugin is ApplicationPlugin<*>) {
                logger.info("Loaded custom plugin: $pluginClassName")
            }
        } catch (e: Exception) {
            logger.warn("Failed to load plugin: $pluginClassName", e)
        }
    }
}
