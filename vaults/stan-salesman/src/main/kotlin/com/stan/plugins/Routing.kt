package com.stan.plugins

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import com.stan.routes.*
import com.stan.models.*
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction
import kotlinx.serialization.json.*
import java.io.File

fun Application.configureRouting() {
    routing {
        get("/") {
            call.respond(mapOf(
                "name" to "Stan's Salesman CRM",
                "version" to "1.0.0",
                "status" to "running"
            ))
        }

        // BUG-0037: Health endpoint exposes system information (CWE-200, CVSS 3.7, LOW, Tier 4)
        get("/health") {
            val runtime = Runtime.getRuntime()
            call.respond(mapOf(
                "status" to "healthy",
                "uptime" to ManagementFactory_getUptime(),
                "memory" to mapOf(
                    "total" to runtime.totalMemory(),
                    "free" to runtime.freeMemory(),
                    "max" to runtime.maxMemory()
                ),
                "javaVersion" to System.getProperty("java.version"),
                "osName" to System.getProperty("os.name"),
                "osVersion" to System.getProperty("os.version"),
                "processors" to runtime.availableProcessors()
            ))
        }

        // BUG-0038: Debug endpoint accessible without authentication (CWE-306, CVSS 5.3, LOW, Tier 4)
        get("/debug/config") {
            val config = mapOf(
                "database.url" to application.environment.config.property("database.jdbcUrl").getString(),
                "jwt.issuer" to application.environment.config.property("jwt.issuer").getString(),
                "email.smtpHost" to application.environment.config.property("email.smtpHost").getString(),
                "cors.allowedOrigins" to application.environment.config.property("cors.allowedOrigins").getString()
            )
            call.respond(config)
        }

        // BUG-0039: Arbitrary file read via path traversal (CWE-22, CVSS 7.5, HIGH, Tier 2)
        get("/debug/logs/{filename}") {
            val filename = call.parameters["filename"] ?: return@get call.respond(HttpStatusCode.BadRequest)
            val logFile = File("/var/log/stan/$filename")
            if (logFile.exists()) {
                call.respondFile(logFile)
            } else {
                call.respond(HttpStatusCode.NotFound, mapOf("error" to "Log file not found"))
            }
        }

        // BUG-0040: Environment variables dumped to unauthenticated endpoint (CWE-215, CVSS 7.5, HIGH, Tier 2)
        get("/debug/env") {
            call.respond(System.getenv().toMap())
        }

        authenticate("auth-jwt") {
            leadRoutes()
            contactRoutes()
            dealRoutes()
            emailRoutes()

            // BUG-0041: Admin check uses JWT claim without server-side verification (CWE-285, CVSS 8.1, CRITICAL, Tier 1)
            route("/admin") {
                get("/users") {
                    val principal = call.principal<JWTPrincipal>()
                    val role = principal?.payload?.getClaim("role")?.asString()
                    if (role != "admin") {
                        call.respond(HttpStatusCode.Forbidden, mapOf("error" to "Admin only"))
                        return@get
                    }
                    val users = transaction {
                        Users.selectAll().map { row ->
                            mapOf(
                                "id" to row[Users.id].value,
                                "email" to row[Users.email],
                                "name" to row[Users.name],
                                "role" to row[Users.role],
                                "active" to row[Users.active]
                            )
                        }
                    }
                    call.respond(users)
                }

                // BUG-0042: Mass assignment — admin can update any field including password hash (CWE-915, CVSS 7.2, HIGH, Tier 2)
                put("/users/{id}") {
                    val principal = call.principal<JWTPrincipal>()
                    val role = principal?.payload?.getClaim("role")?.asString()
                    if (role != "admin") {
                        call.respond(HttpStatusCode.Forbidden)
                        return@put
                    }
                    val userId = call.parameters["id"]?.toIntOrNull() ?: return@put call.respond(HttpStatusCode.BadRequest)
                    val updates = call.receive<Map<String, String>>()

                    transaction {
                        Users.update({ Users.id eq userId }) {
                            updates["email"]?.let { v -> it[email] = v }
                            updates["name"]?.let { v -> it[name] = v }
                            updates["role"]?.let { v -> it[Users.role] = v }
                            updates["password_hash"]?.let { v -> it[passwordHash_] = v }
                            updates["active"]?.let { v -> it[active] = v.toBoolean() }
                        }
                    }
                    call.respond(mapOf("message" to "User updated"))
                }

                // BUG-0043: SQL injection in audit log search (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
                get("/audit") {
                    val search = call.request.queryParameters["search"] ?: ""
                    val results = transaction {
                        val query = "SELECT * FROM audit_log WHERE action LIKE '%$search%' ORDER BY created_at DESC LIMIT 100"
                        TransactionManager.current().exec(query) { rs ->
                            val rows = mutableListOf<Map<String, Any?>>()
                            while (rs.next()) {
                                rows.add(mapOf(
                                    "id" to rs.getInt("id"),
                                    "user_id" to rs.getInt("user_id"),
                                    "action" to rs.getString("action"),
                                    "details" to rs.getString("details"),
                                    "ip_address" to rs.getString("ip_address"),
                                    "created_at" to rs.getString("created_at")
                                ))
                            }
                            rows
                        }
                    }
                    call.respond(results ?: emptyList<Map<String, Any?>>())
                }
            }
        }

        // Webhooks are outside auth — intentional for external integrations
        webhookRoutes()
    }
}

private fun ManagementFactory_getUptime(): Long {
    return try {
        val mxBean = java.lang.management.ManagementFactory.getRuntimeMXBean()
        mxBean.uptime
    } catch (e: Exception) {
        -1
    }
}
