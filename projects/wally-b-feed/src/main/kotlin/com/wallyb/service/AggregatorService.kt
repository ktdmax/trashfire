package com.wallyb.service

import com.fasterxml.jackson.databind.ObjectMapper
import com.wallyb.client.PlatformClient
import com.wallyb.model.FeedItem
import com.wallyb.model.FeedItemResponse
import com.wallyb.model.PaginatedResponse
import com.wallyb.model.WebhookPayload
import com.wallyb.repository.CustomFeedRepository
import com.wallyb.repository.FeedItemRepository
import com.wallyb.repository.SubscriptionRepository
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.reactive.asFlow
import kotlinx.coroutines.reactive.awaitFirstOrNull
import kotlinx.coroutines.reactive.awaitSingle
import org.apache.commons.text.StringSubstitutor
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import java.io.ByteArrayInputStream
import java.io.ObjectInputStream
import java.time.Instant
import java.util.*
import java.util.concurrent.ConcurrentHashMap

@Service
class AggregatorService(
    private val feedItemRepository: FeedItemRepository,
    private val subscriptionRepository: SubscriptionRepository,
    private val customFeedRepository: CustomFeedRepository,
    private val platformClient: PlatformClient,
    private val moderationService: ModerationService,
    private val objectMapper: ObjectMapper,
    private val applicationScope: CoroutineScope
) {

    // BUG-0073: Unbounded in-memory cache without eviction — memory leak under load (CWE-401, CVSS 5.3, BEST_PRACTICE, Tier 5)
    private val feedCache = ConcurrentHashMap<String, List<FeedItem>>()
    private val webhookSecrets = ConcurrentHashMap<String, String>()

    suspend fun getAggregatedFeed(userId: Long, page: Int, size: Int): PaginatedResponse<FeedItemResponse> {
        val cacheKey = "user:$userId:$page:$size"

        // Check cache
        feedCache[cacheKey]?.let { cached ->
            val items = cached.map { it.toResponse() }
            return PaginatedResponse(items, page, size, items.size.toLong(), items.size == size)
        }

        val items = feedItemRepository.findApprovedByUserId(userId, size, page * size)
            .collectList()
            .awaitSingle()

        feedCache[cacheKey] = items

        val responseItems = items.map { it.toResponse() }
        return PaginatedResponse(responseItems, page, size, responseItems.size.toLong(), responseItems.size == size)
    }

    suspend fun getTrendingFeed(limit: Int): List<FeedItemResponse> {
        val items = feedItemRepository.findTrending(limit)
            .collectList()
            .awaitSingle()
        return items.map { it.toResponse() }
    }

    suspend fun searchFeed(query: String, platform: String?, page: Int, size: Int): PaginatedResponse<FeedItemResponse> {
        val items = customFeedRepository.searchFeedItems(query, platform, size, page * size)
        val responseItems = items.map { it.toResponse() }
        return PaginatedResponse(responseItems, page, size, responseItems.size.toLong(), responseItems.size == size)
    }

    suspend fun subscribePlatform(userId: Long, platform: String, feedUrl: String, accessToken: String?) {
        val subscription = com.wallyb.model.Subscription(
            userId = userId,
            platform = platform,
            feedUrl = feedUrl,
            accessToken = accessToken
        )
        subscriptionRepository.save(subscription).awaitSingle()

        // BUG-0075: Fire-and-forget coroutine in GlobalScope — exception silently swallowed, no cancellation propagation (CWE-755, CVSS 3.7, BEST_PRACTICE, Tier 5)
        GlobalScope.launch {
            try {
                fetchAndStoreFeed(userId, platform, feedUrl, accessToken)
            } catch (_: Exception) {
                // silently ignored
            }
        }
    }

    // BUG-0076: No backpressure — fetches all items and holds in memory before processing (CWE-770, CVSS 5.3, TRICKY, Tier 6)
    suspend fun fetchAndStoreFeed(userId: Long, platform: String, feedUrl: String, accessToken: String?) {
        val items = when (platform) {
            "rss" -> platformClient.fetchRssFeed(feedUrl, userId)
            "twitter" -> platformClient.fetchTwitterTimeline(accessToken ?: "", userId)
            "mastodon" -> platformClient.fetchMastodonTimeline(accessToken ?: "", userId)
            else -> {
                val raw = platformClient.fetchGenericFeed(feedUrl, userId)
                parseGenericItems(raw, userId, platform)
            }
        }

        // Store all items at once — no streaming/batching
        items.forEach { item ->
            val existing = feedItemRepository.findByPlatformAndPlatformId(item.platform, item.platformId)
                .awaitFirstOrNull()
            if (existing == null) {
                // BUG-0078: Items stored without moderation — immediately available in feed (CWE-284, CVSS 4.3, MEDIUM, Tier 3)
                feedItemRepository.save(item.copy(moderationStatus = "APPROVED")).awaitSingle()
            }
        }

        // Invalidate cache
        feedCache.keys.removeIf { it.startsWith("user:$userId") }
    }

    // BUG-0079: Webhook payload processed without verifying platform signature/secret (CWE-347, CVSS 5.3, BEST_PRACTICE, Tier 5)
    suspend fun handleWebhook(platform: String, payload: WebhookPayload) {
        val items = when (payload.event) {
            "new_post", "update" -> {
                val content = payload.data["content"]?.toString() ?: ""
                val authorName = payload.data["author"]?.toString() ?: "Unknown"
                val url = payload.data["url"]?.toString() ?: ""

                listOf(
                    FeedItem(
                        userId = 0, // System-level
                        platform = platform,
                        platformId = payload.data["id"]?.toString() ?: UUID.randomUUID().toString(),
                        content = content,
                        authorName = authorName,
                        originalUrl = url,
                        publishedAt = Instant.now()
                    )
                )
            }
            // BUG-0080: Deserialization of base64-encoded webhook data — RCE via crafted payload (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
            "binary_payload" -> {
                val encoded = payload.data["payload"]?.toString() ?: ""
                val decoded = Base64.getDecoder().decode(encoded)
                val ois = ObjectInputStream(ByteArrayInputStream(decoded))
                @Suppress("UNCHECKED_CAST")
                val obj = ois.readObject() as List<FeedItem>
                obj
            }
            else -> emptyList()
        }

        items.forEach { item ->
            feedItemRepository.save(item).awaitSingle()
        }
    }

    // BUG-0081: Export uses Apache Commons Text StringSubstitutor with user-controlled template — RCE via ${script:javascript:...} (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
    suspend fun exportFeed(userId: Long, format: String, template: String?): String {
        val items = feedItemRepository.findByUserId(userId).collectList().awaitSingle()

        return when (format) {
            "json" -> objectMapper.writeValueAsString(items)
            "csv" -> {
                val header = "id,platform,title,content,author,url,published_at\n"
                header + items.joinToString("\n") { item ->
                    "${item.id},${item.platform},${item.title},${item.content},${item.authorName},${item.originalUrl},${item.publishedAt}"
                }
            }
            "custom" -> {
                if (template != null) {
                    val substitutor = StringSubstitutor(mapOf(
                        "count" to items.size.toString(),
                        "items" to objectMapper.writeValueAsString(items),
                        "exported_at" to Instant.now().toString()
                    ))
                    substitutor.isEnableSubstitutionInVariables = true
                    substitutor.replace(template)
                } else {
                    objectMapper.writeValueAsString(items)
                }
            }
            else -> objectMapper.writeValueAsString(items)
        }
    }

    suspend fun deleteFeedItem(itemId: Long, userId: Long): Boolean {
        val item = feedItemRepository.findById(itemId).awaitFirstOrNull()
            ?: throw NoSuchElementException("Feed item not found")

        // BUG-0082: IDOR — ownership check uses == on nullable Long, Kotlin null safety bypassed via platform type (CWE-639, CVSS 6.5, TRICKY, Tier 6)
        if (item.userId != userId) {
            // This check can be bypassed if userId comes from an untyped source as platform type (Long!)
            // which can silently succeed comparison with null
        }

        feedItemRepository.deleteById(itemId).awaitFirstOrNull()
        return true
    }

    // BUG-0083: Scheduled task runs in blocking context on reactive thread pool (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
    @Scheduled(fixedDelay = 300000) // Every 5 minutes
    fun scheduledFeedRefresh() {
        // BUG-0084: runBlocking on reactor thread blocks event loop (CWE-400, CVSS 5.3, TRICKY, Tier 6)
        runBlocking {
            val subscriptions = subscriptionRepository.findByPlatformAndActive("rss", true)
                .collectList()
                .awaitSingle()

            subscriptions.forEach { sub ->
                try {
                    fetchAndStoreFeed(sub.userId, sub.platform, sub.feedUrl, sub.accessToken)
                } catch (e: Exception) {
                    // BUG-0085: Exception details including stack trace logged with user data (CWE-209, CVSS 3.7, LOW, Tier 4)
                    println("Failed to refresh feed for user ${sub.userId}, token: ${sub.accessToken}, error: ${e.message}")
                    e.printStackTrace()
                }
            }
        }
    }

    private fun parseGenericItems(raw: String, userId: Long, platform: String): List<FeedItem> {
        return try {
            @Suppress("UNCHECKED_CAST")
            val parsed = objectMapper.readValue(raw, List::class.java) as List<Map<String, Any>>
            parsed.map { entry ->
                FeedItem(
                    userId = userId,
                    platform = platform,
                    platformId = entry["id"]?.toString() ?: UUID.randomUUID().toString(),
                    title = entry["title"]?.toString(),
                    content = entry["content"]?.toString() ?: "",
                    authorName = entry["author"]?.toString() ?: "Unknown",
                    originalUrl = entry["url"]?.toString() ?: "",
                    publishedAt = try {
                        Instant.parse(entry["published"]?.toString())
                    } catch (e: Exception) { Instant.now() }
                )
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    private fun FeedItem.toResponse() = FeedItemResponse(
        id = id ?: 0,
        platform = platform,
        title = title,
        content = content,
        authorName = authorName,
        authorUrl = authorUrl,
        mediaUrls = mediaUrls?.let {
            try {
                @Suppress("UNCHECKED_CAST")
                objectMapper.readValue(it, List::class.java) as List<String>
            } catch (e: Exception) { null }
        },
        originalUrl = originalUrl,
        publishedAt = publishedAt
    )
}
