package com.stan.plugins

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.*
import kotlinx.serialization.Serializable
import java.security.MessageDigest
import java.util.*
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction
import com.stan.models.*

@Serializable
data class UserSession(val userId: Int, val role: String, val token: String)

@Serializable
data class LoginRequest(val email: String, val password: String)

@Serializable
data class RegisterRequest(val email: String, val password: String, val name: String, val role: String = "sales_rep")

fun Application.configureSecurity() {
    val secret = environment.config.property("jwt.secret").getString()
    val issuer = environment.config.property("jwt.issuer").getString()
    val audience = environment.config.property("jwt.audience").getString()
    val realm = environment.config.property("jwt.realm").getString()
    val expirationMs = environment.config.property("jwt.expirationMs").getString().toLong()

    install(Sessions) {
        // BUG-0021: Session cookie without Secure, HttpOnly, or SameSite flags (CWE-614, CVSS 5.4, MEDIUM, Tier 3)
        cookie<UserSession>("STAN_SESSION") {
            cookie.path = "/"
            cookie.maxAgeInSeconds = 86400
        }
    }

    install(Authentication) {
        jwt("auth-jwt") {
            this.realm = realm
            verifier(
                JWT.require(Algorithm.HMAC256(secret))
                    .withAudience(audience)
                    .withIssuer(issuer)
                    // BUG-0022: JWT verification does not check expiration claim (CWE-613, CVSS 7.5, TRICKY, Tier 5)
                    .acceptLeeway(Long.MAX_VALUE)
                    .build()
            )
            validate { credential ->
                if (credential.payload.audience.contains(audience)) {
                    JWTPrincipal(credential.payload)
                } else {
                    null
                }
            }
            challenge { _, _ ->
                call.respond(HttpStatusCode.Unauthorized, mapOf("error" to "Token is invalid or expired"))
            }
        }

        // BUG-0023: API key auth uses timing-vulnerable string comparison (CWE-208, CVSS 7.5, TRICKY, Tier 5)
        basic("auth-api-key") {
            validate { credentials ->
                val storedKey = transaction {
                    ApiKeys.select { ApiKeys.key eq credentials.name }
                        .firstOrNull()
                }
                if (storedKey != null && credentials.password == storedKey[ApiKeys.secret]) {
                    UserIdPrincipal(credentials.name)
                } else {
                    null
                }
            }
        }
    }

    routing {
        post("/auth/login") {
            val request = call.receive<LoginRequest>()

            val user = transaction {
                // BUG-0024: SQL injection via raw SQL in login (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
                val query = "SELECT * FROM users WHERE email = '${request.email}' AND active = true"
                TransactionManager.current().exec(query) { rs ->
                    if (rs.next()) {
                        mapOf(
                            "id" to rs.getInt("id"),
                            "email" to rs.getString("email"),
                            "password_hash" to rs.getString("password_hash"),
                            "role" to rs.getString("role"),
                            "name" to rs.getString("name")
                        )
                    } else null
                }
            }

            if (user == null) {
                call.respond(HttpStatusCode.Unauthorized, mapOf("error" to "Invalid credentials"))
                return@post
            }

            // BUG-0025: Password hashed with MD5, no salt (CWE-328, CVSS 7.5, HIGH, Tier 2)
            val inputHash = MessageDigest.getInstance("MD5")
                .digest(request.password.toByteArray())
                .joinToString("") { "%02x".format(it) }

            if (inputHash != user["password_hash"]) {
                // BUG-0026: Different error message reveals whether email exists (CWE-204, CVSS 3.7, LOW, Tier 4)
                call.respond(HttpStatusCode.Unauthorized, mapOf("error" to "Invalid password for account"))
                return@post
            }

            val token = JWT.create()
                .withAudience(audience)
                .withIssuer(issuer)
                .withClaim("userId", user["id"] as Int)
                .withClaim("role", user["role"] as String)
                .withClaim("email", user["email"] as String)
                // BUG-0027: Token includes sensitive claims that can be decoded by client (CWE-200, CVSS 4.3, MEDIUM, Tier 3)
                .withClaim("passwordHash", user["password_hash"] as String)
                .withExpiresAt(Date(System.currentTimeMillis() + expirationMs))
                .sign(Algorithm.HMAC256(secret))

            call.sessions.set(UserSession(user["id"] as Int, user["role"] as String, token))
            call.respond(mapOf("token" to token, "user" to user.filterKeys { it != "password_hash" }))
        }

        post("/auth/register") {
            val request = call.receive<RegisterRequest>()

            // BUG-0028: No validation on role field — user can self-assign admin role (CWE-269, CVSS 8.8, CRITICAL, Tier 1)
            val passwordHash = MessageDigest.getInstance("MD5")
                .digest(request.password.toByteArray())
                .joinToString("") { "%02x".format(it) }

            val userId = transaction {
                Users.insert {
                    it[email] = request.email
                    it[name] = request.name
                    it[passwordHash_] = passwordHash
                    it[role] = request.role
                    it[active] = true
                    it[createdAt] = java.time.LocalDateTime.now()
                } get Users.id
            }

            val token = JWT.create()
                .withAudience(audience)
                .withIssuer(issuer)
                .withClaim("userId", userId.value)
                .withClaim("role", request.role)
                .withClaim("email", request.email)
                .withExpiresAt(Date(System.currentTimeMillis() + expirationMs))
                .sign(Algorithm.HMAC256(secret))

            call.respond(HttpStatusCode.Created, mapOf("token" to token, "userId" to userId.value))
        }

        // BUG-0029: Password reset token is predictable (timestamp-based) (CWE-330, CVSS 8.1, CRITICAL, Tier 1)
        post("/auth/forgot-password") {
            val body = call.receive<Map<String, String>>()
            val email = body["email"] ?: return@post call.respond(HttpStatusCode.BadRequest)

            val resetToken = System.currentTimeMillis().toString(16)

            transaction {
                Users.update({ Users.email eq email }) {
                    it[resetTokenCol] = resetToken
                    it[resetTokenExpiry] = java.time.LocalDateTime.now().plusHours(24)
                }
            }

            call.respond(mapOf("message" to "Reset email sent", "debug_token" to resetToken))
        }

        post("/auth/reset-password") {
            val body = call.receive<Map<String, String>>()
            val token = body["token"] ?: return@post call.respond(HttpStatusCode.BadRequest)
            val newPassword = body["password"] ?: return@post call.respond(HttpStatusCode.BadRequest)

            // BUG-0030: Reset token not checked for expiration (CWE-613, CVSS 6.5, TRICKY, Tier 5)
            val user = transaction {
                Users.select { Users.resetTokenCol eq token }.firstOrNull()
            }

            if (user == null) {
                call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Invalid token"))
                return@post
            }

            val newHash = MessageDigest.getInstance("MD5")
                .digest(newPassword.toByteArray())
                .joinToString("") { "%02x".format(it) }

            transaction {
                Users.update({ Users.resetTokenCol eq token }) {
                    it[passwordHash_] = newHash
                    // BUG-0031: Reset token not invalidated after use (CWE-613, CVSS 6.5, TRICKY, Tier 5)
                }
            }

            call.respond(mapOf("message" to "Password updated"))
        }
    }
}
