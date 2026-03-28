package com.wallyb.handler

import com.wallyb.model.LoginRequest
import com.wallyb.model.RegisterRequest
import com.wallyb.service.UserService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.reactive.awaitFirstOrNull
import kotlinx.coroutines.withContext
import org.springframework.core.env.Environment
import org.springframework.http.MediaType
import org.springframework.http.codec.multipart.FilePart
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.server.*
import java.io.File
import java.nio.file.Paths

@Component
class UserHandler(
    private val userService: UserService,
    private val environment: Environment
) {

    suspend fun register(request: ServerRequest): ServerResponse {
        val body = request.awaitBody<RegisterRequest>()
        return try {
            val response = userService.register(body)
            ServerResponse.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValueAndAwait(response)
        } catch (e: IllegalArgumentException) {
            // BUG-0100: Error message reveals whether username or email exists — account enumeration (CWE-204, CVSS 3.7, LOW, Tier 4)
            ServerResponse.badRequest()
                .bodyValueAndAwait(mapOf("error" to e.message))
        }
    }

    suspend fun login(request: ServerRequest): ServerResponse {
        val body = request.awaitBody<LoginRequest>()
        return try {
            val response = userService.login(body)
            ServerResponse.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValueAndAwait(response)
        } catch (e: IllegalArgumentException) {
            ServerResponse.status(401)
                .bodyValueAndAwait(mapOf("error" to "Invalid credentials"))
        }
    }

    suspend fun refreshToken(request: ServerRequest): ServerResponse {
        val body = request.awaitBody<Map<String, String>>()
        val refreshToken = body["refreshToken"]
            ?: return ServerResponse.badRequest().bodyValueAndAwait(mapOf("error" to "Missing refresh token"))

        // Placeholder — in production would validate and reissue
        return ServerResponse.ok()
            .bodyValueAndAwait(mapOf("status" to "refreshed"))
    }

    suspend fun resetPassword(request: ServerRequest): ServerResponse {
        val email = request.queryParamOrNull("email")
        val token = request.queryParamOrNull("token")
        val newPassword = request.queryParamOrNull("newPassword")

        return if (email != null && token == null) {
            // Initiate reset
            val resetToken = userService.initiatePasswordReset(email)
            ServerResponse.ok()
                .bodyValueAndAwait(mapOf("resetToken" to resetToken, "message" to "Reset initiated"))
        } else if (token != null && newPassword != null) {
            // Complete reset
            userService.resetPassword(token, newPassword)
            ServerResponse.ok()
                .bodyValueAndAwait(mapOf("message" to "Password reset successful"))
        } else {
            ServerResponse.badRequest()
                .bodyValueAndAwait(mapOf("error" to "Missing parameters"))
        }
    }

    suspend fun getCurrentUser(request: ServerRequest): ServerResponse {
        val userId = extractUserId(request)
        val profile = userService.getUserById(userId)
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(profile)
    }

    suspend fun updateProfile(request: ServerRequest): ServerResponse {
        val userId = extractUserId(request)
        val updates = request.awaitBody<Map<String, Any?>>()
        val user = userService.updateProfile(userId, updates)
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(user)
    }

    suspend fun getUserProfile(request: ServerRequest): ServerResponse {
        val userId = request.pathVariable("userId").toLong()
        val profile = userService.getUserById(userId)
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(profile)
    }

    suspend fun bulkLookup(request: ServerRequest): ServerResponse {
        val body = request.awaitBody<Map<String, List<Long>>>()
        val userIds = body["userIds"] ?: emptyList()
        val users = userService.bulkLookup(userIds)
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(users)
    }

    // BUG-0101: Path traversal in avatar upload — filename not sanitized (CWE-22, CVSS 7.5, HIGH, Tier 2)
    suspend fun uploadAvatar(request: ServerRequest): ServerResponse {
        val userId = extractUserId(request)
        val multipartData = request.awaitMultipartData()
        val filePart = multipartData["avatar"]?.firstOrNull() as? FilePart
            ?: return ServerResponse.badRequest().bodyValueAndAwait(mapOf("error" to "No file uploaded"))

        // BUG-0102: No file type validation — allows uploading executable files as "avatars" (CWE-434, CVSS 7.5, HIGH, Tier 2)
        val filename = filePart.filename()
        val uploadDir = "/var/uploads/avatars"

        // filename could be "../../../etc/cron.d/reverse-shell"
        val targetPath = Paths.get(uploadDir, filename)

        withContext(Dispatchers.IO) {
            val file = targetPath.toFile()
            file.parentFile?.mkdirs()
            filePart.transferTo(file).awaitFirstOrNull()
        }

        val avatarUrl = "/uploads/avatars/$filename"
        userService.updateProfile(userId, mapOf("avatarUrl" to avatarUrl))

        return ServerResponse.ok()
            .bodyValueAndAwait(mapOf("avatarUrl" to avatarUrl))
    }

    suspend fun listAllUsers(request: ServerRequest): ServerResponse {
        // Admin endpoint — but authorization is only pattern-based, not role-verified in handler
        val users = userService.bulkLookup((1L..1000L).toList())
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(users)
    }

    suspend fun deleteUser(request: ServerRequest): ServerResponse {
        val userId = request.pathVariable("userId").toLong()
        userService.deleteUser(userId)
        return ServerResponse.noContent().buildAndAwait()
    }

    suspend fun changeUserRole(request: ServerRequest): ServerResponse {
        val userId = request.pathVariable("userId").toLong()
        val body = request.awaitBody<Map<String, String>>()
        val newRole = body["role"] ?: return ServerResponse.badRequest()
            .bodyValueAndAwait(mapOf("error" to "Role required"))

        val user = userService.changeUserRole(userId, newRole)
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(user)
    }

    // BUG-0103: Debug endpoint exposes all environment variables including secrets (CWE-200, CVSS 7.5, HIGH, Tier 2)
    suspend fun debugEnv(request: ServerRequest): ServerResponse {
        val envVars = System.getenv()
        val springProps = mapOf(
            "db.url" to (environment.getProperty("spring.r2dbc.url") ?: ""),
            "db.username" to (environment.getProperty("spring.r2dbc.username") ?: ""),
            "db.password" to (environment.getProperty("spring.r2dbc.password") ?: ""),
            "jwt.secret" to (environment.getProperty("app.jwt.secret") ?: ""),
            "twitter.api-key" to (environment.getProperty("app.platforms.twitter.api-key") ?: ""),
            "mastodon.token" to (environment.getProperty("app.platforms.mastodon.access-token") ?: "")
        )

        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(mapOf(
                "environment" to envVars,
                "springProperties" to springProps,
                "javaVersion" to System.getProperty("java.version"),
                "osInfo" to mapOf(
                    "name" to System.getProperty("os.name"),
                    "arch" to System.getProperty("os.arch")
                )
            ))
    }

    // BUG-0104: Debug endpoint exposes database connection pool details (CWE-200, CVSS 5.3, LOW, Tier 4)
    suspend fun debugConnections(request: ServerRequest): ServerResponse {
        val runtime = Runtime.getRuntime()
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(mapOf(
                "freeMemory" to runtime.freeMemory(),
                "totalMemory" to runtime.totalMemory(),
                "maxMemory" to runtime.maxMemory(),
                "processors" to runtime.availableProcessors(),
                "threads" to Thread.activeCount(),
                "classPath" to System.getProperty("java.class.path")
            ))
    }

    private suspend fun extractUserId(request: ServerRequest): Long {
        val context = ReactiveSecurityContextHolder.getContext().awaitFirstOrNull()
        return context?.authentication?.principal?.toString()?.toLongOrNull()
            ?: throw IllegalStateException("Not authenticated")
    }
}
