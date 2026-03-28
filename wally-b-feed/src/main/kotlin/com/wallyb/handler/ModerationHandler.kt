package com.wallyb.handler

import com.wallyb.model.BulkModerationRequest
import com.wallyb.model.ModerationDecision
import com.wallyb.model.ModerationReport
import com.wallyb.service.ModerationService
import kotlinx.coroutines.reactive.awaitFirstOrNull
import org.springframework.http.MediaType
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.server.*

@Component
class ModerationHandler(
    private val moderationService: ModerationService
) {

    suspend fun analyzeContent(request: ServerRequest): ServerResponse {
        val body = request.awaitBody<Map<String, String>>()
        val content = body["content"]
            ?: return ServerResponse.badRequest().bodyValueAndAwait(mapOf("error" to "Content required"))

        val analysis = moderationService.analyzeContent(content)
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(analysis)
    }

    suspend fun reportContent(request: ServerRequest): ServerResponse {
        val userId = extractUserId(request)
        val body = request.awaitBody<Map<String, Any>>()

        val feedItemId = (body["feedItemId"] as? Number)?.toLong()
            ?: return ServerResponse.badRequest().bodyValueAndAwait(mapOf("error" to "feedItemId required"))
        val reason = body["reason"]?.toString()
            ?: return ServerResponse.badRequest().bodyValueAndAwait(mapOf("error" to "reason required"))

        val report = moderationService.reportContent(feedItemId, userId, reason)
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(report)
    }

    suspend fun getModerationQueue(request: ServerRequest): ServerResponse {
        val queue = moderationService.getModerationQueue()
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(queue)
    }

    suspend fun makeDecision(request: ServerRequest): ServerResponse {
        val reportId = request.pathVariable("reportId").toLong()
        val userId = extractUserId(request)
        val decision = request.awaitBody<ModerationDecision>()

        val report = moderationService.makeDecision(reportId, userId, decision)
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(report)
    }

    suspend fun bulkModeration(request: ServerRequest): ServerResponse {
        val userId = extractUserId(request)
        val body = request.awaitBody<BulkModerationRequest>()

        moderationService.bulkModeration(body, userId)
        return ServerResponse.ok()
            .bodyValueAndAwait(mapOf(
                "status" to "completed",
                "processedCount" to body.itemIds.size
            ))
    }

    // BUG-0105: Moderation bypass endpoint accessible without authentication check (CWE-284, CVSS 5.3, BEST_PRACTICE, Tier 5)
    suspend fun bypassModeration(request: ServerRequest): ServerResponse {
        val body = request.awaitBody<Map<String, Any>>()
        val itemId = (body["itemId"] as? Number)?.toLong()
            ?: return ServerResponse.badRequest().bodyValueAndAwait(mapOf("error" to "itemId required"))

        // BUG-0106: Exports moderation log with user-controlled filename — path traversal (CWE-22, CVSS 7.5, TRICKY, Tier 6)
        val logFilename = body["logFile"]?.toString()
        if (logFilename != null) {
            moderationService.exportModerationLog(logFilename)
        }

        val item = moderationService.bypassModeration(itemId)
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(item)
    }

    // RH-007: Looks like it might be vulnerable to IDOR, but actually validates the authenticated user's role
    private suspend fun extractUserId(request: ServerRequest): Long {
        val context = ReactiveSecurityContextHolder.getContext().awaitFirstOrNull()
        val auth = context?.authentication
            ?: throw IllegalStateException("Not authenticated")

        // Actually checks authentication is valid before extracting principal
        if (!auth.isAuthenticated) {
            throw IllegalStateException("Not authenticated")
        }

        return auth.principal?.toString()?.toLongOrNull()
            ?: throw IllegalStateException("Invalid principal")
    }
}
