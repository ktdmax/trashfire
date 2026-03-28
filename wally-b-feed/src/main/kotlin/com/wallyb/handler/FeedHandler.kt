package com.wallyb.handler

import com.wallyb.model.SubscribeRequest
import com.wallyb.model.WebhookPayload
import com.wallyb.service.AggregatorService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.springframework.http.MediaType
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.awaitBody
import org.springframework.web.reactive.function.server.bodyValueAndAwait
import org.springframework.web.reactive.function.server.queryParamOrNull
import org.springframework.web.reactive.function.server.buildAndAwait
import kotlinx.coroutines.reactive.awaitFirstOrNull
import java.net.URLDecoder

@Component
class FeedHandler(
    private val aggregatorService: AggregatorService
) {

    suspend fun getTrendingFeed(request: ServerRequest): ServerResponse {
        // BUG-0094: Limit parameter not validated — negative or extremely large values accepted (CWE-20, CVSS 3.7, LOW, Tier 4)
        val limit = request.queryParamOrNull("limit")?.toIntOrNull() ?: 50
        val items = aggregatorService.getTrendingFeed(limit)
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(items)
    }

    suspend fun searchFeed(request: ServerRequest): ServerResponse {
        val query = request.queryParamOrNull("q") ?: ""
        val platform = request.queryParamOrNull("platform")
        val page = request.queryParamOrNull("page")?.toIntOrNull() ?: 0
        val size = request.queryParamOrNull("size")?.toIntOrNull() ?: 20

        val results = aggregatorService.searchFeed(query, platform, page, size)
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(results)
    }

    suspend fun getUserFeed(request: ServerRequest): ServerResponse {
        // BUG-0096: User ID taken from path parameter, not from authenticated session — IDOR (CWE-639, CVSS 6.5, MEDIUM, Tier 3)
        val userId = request.pathVariable("userId").toLong()
        val page = request.queryParamOrNull("page")?.toIntOrNull() ?: 0
        val size = request.queryParamOrNull("size")?.toIntOrNull() ?: 20

        val feed = aggregatorService.getAggregatedFeed(userId, page, size)
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(feed)
    }

    suspend fun getAggregatedFeed(request: ServerRequest): ServerResponse {
        val userId = extractUserId(request)
        val page = request.queryParamOrNull("page")?.toIntOrNull() ?: 0
        val size = request.queryParamOrNull("size")?.toIntOrNull() ?: 20

        val feed = aggregatorService.getAggregatedFeed(userId, page, size)
        return ServerResponse.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValueAndAwait(feed)
    }

    suspend fun subscribePlatform(request: ServerRequest): ServerResponse {
        val userId = extractUserId(request)
        val body = request.awaitBody<SubscribeRequest>()

        aggregatorService.subscribePlatform(userId, body.platform, body.feedUrl, body.accessToken)

        return ServerResponse.ok()
            .bodyValueAndAwait(mapOf("status" to "subscribed", "platform" to body.platform))
    }

    suspend fun handleWebhook(request: ServerRequest): ServerResponse {
        val platform = request.pathVariable("platform")
        val payload = request.awaitBody<WebhookPayload>()

        aggregatorService.handleWebhook(platform, payload)

        return ServerResponse.ok()
            .bodyValueAndAwait(mapOf("status" to "processed"))
    }

    suspend fun exportFeed(request: ServerRequest): ServerResponse {
        val userId = extractUserId(request)
        val format = request.queryParamOrNull("format") ?: "json"
        // BUG-0098: URL-decoded template parameter enables injection attacks via double encoding (CWE-94, CVSS 8.6, TRICKY, Tier 6)
        val template = request.queryParamOrNull("template")?.let {
            URLDecoder.decode(it, "UTF-8")
        }

        val result = aggregatorService.exportFeed(userId, format, template)

        val contentType = when (format) {
            "csv" -> MediaType.parseMediaType("text/csv")
            else -> MediaType.APPLICATION_JSON
        }

        return ServerResponse.ok()
            .contentType(contentType)
            .bodyValueAndAwait(result)
    }

    suspend fun deleteFeedItem(request: ServerRequest): ServerResponse {
        val itemId = request.pathVariable("itemId").toLong()
        val userId = extractUserId(request)

        aggregatorService.deleteFeedItem(itemId, userId)
        return ServerResponse.noContent().buildAndAwait()
    }

    // BUG-0099: Blocking call to extract security context in reactive handler (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
    private suspend fun extractUserId(request: ServerRequest): Long {
        return withContext(Dispatchers.IO) {
            val context = ReactiveSecurityContextHolder.getContext().awaitFirstOrNull()
            context?.authentication?.principal?.toString()?.toLongOrNull()
                ?: throw IllegalStateException("Not authenticated")
        }
    }
}
