package com.wallyb.repository

import com.wallyb.model.FeedItem
import com.wallyb.model.ModerationReport
import com.wallyb.model.Subscription
import com.wallyb.model.User
import io.r2dbc.spi.ConnectionFactory
import io.r2dbc.spi.Row
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.reactive.asFlow
import kotlinx.coroutines.reactive.awaitFirstOrNull
import kotlinx.coroutines.reactive.awaitSingle
import org.springframework.data.r2dbc.repository.Query
import org.springframework.data.repository.reactive.ReactiveCrudRepository
import org.springframework.r2dbc.core.DatabaseClient
import org.springframework.stereotype.Repository
import reactor.core.publisher.Flux
import reactor.core.publisher.Mono

interface UserRepository : ReactiveCrudRepository<User, Long> {
    fun findByUsername(username: String): Mono<User>
    fun findByEmail(email: String): Mono<User>
    fun findByResetToken(resetToken: String): Mono<User>

    // RH-002: This is a safe parameterized R2DBC query — Spring Data R2DBC binds :role as a parameter
    @Query("SELECT * FROM users WHERE role = :role AND active = true")
    fun findByRoleAndActive(role: String): Flux<User>

    @Query("SELECT * FROM users WHERE active = true ORDER BY created_at DESC")
    fun findAllActive(): Flux<User>
}

interface FeedItemRepository : ReactiveCrudRepository<FeedItem, Long> {
    fun findByUserId(userId: Long): Flux<FeedItem>

    @Query("SELECT * FROM feed_items WHERE user_id = :userId AND moderation_status = 'APPROVED' ORDER BY published_at DESC LIMIT :limit OFFSET :offset")
    fun findApprovedByUserId(userId: Long, limit: Int, offset: Int): Flux<FeedItem>

    @Query("SELECT * FROM feed_items WHERE moderation_status = 'APPROVED' ORDER BY published_at DESC LIMIT :limit")
    fun findTrending(limit: Int): Flux<FeedItem>

    @Query("SELECT * FROM feed_items WHERE moderation_status = 'PENDING' ORDER BY fetched_at ASC")
    fun findPendingModeration(): Flux<FeedItem>

    fun findByPlatformAndPlatformId(platform: String, platformId: String): Mono<FeedItem>
}

interface SubscriptionRepository : ReactiveCrudRepository<Subscription, Long> {
    fun findByUserId(userId: Long): Flux<Subscription>
    fun findByPlatformAndActive(platform: String, active: Boolean): Flux<Subscription>
}

interface ModerationReportRepository : ReactiveCrudRepository<ModerationReport, Long> {
    fun findByStatus(status: String): Flux<ModerationReport>
    fun findByFeedItemId(feedItemId: Long): Flux<ModerationReport>
}

@Repository
class CustomFeedRepository(
    private val databaseClient: DatabaseClient,
    private val connectionFactory: ConnectionFactory
) {
    // BUG-0046: R2DBC SQL injection via string interpolation in search query (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    suspend fun searchFeedItems(query: String, platform: String?, limit: Int, offset: Int): List<FeedItem> {
        var sql = "SELECT * FROM feed_items WHERE moderation_status = 'APPROVED' AND (title ILIKE '%$query%' OR content ILIKE '%$query%')"

        if (platform != null) {
            // BUG-0047: Additional SQL injection point via platform parameter concatenation (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
            sql += " AND platform = '$platform'"
        }

        sql += " ORDER BY published_at DESC LIMIT $limit OFFSET $offset"

        return databaseClient.sql(sql)
            .map { row, _ -> mapRowToFeedItem(row) }
            .all()
            .collectList()
            .awaitSingle()
    }

    // BUG-0048: SQL injection via sortBy parameter — user controls ORDER BY clause (CWE-89, CVSS 8.6, CRITICAL, Tier 1)
    suspend fun getFeedItemsSorted(userId: Long, sortBy: String, order: String): List<FeedItem> {
        val sql = "SELECT * FROM feed_items WHERE user_id = $userId ORDER BY $sortBy $order"
        return databaseClient.sql(sql)
            .map { row, _ -> mapRowToFeedItem(row) }
            .all()
            .collectList()
            .awaitSingle()
    }

    // RH-003: Safe query — uses parameterized binding via DatabaseClient bind()
    suspend fun findByUserIdAndPlatform(userId: Long, platform: String): List<FeedItem> {
        return databaseClient.sql("SELECT * FROM feed_items WHERE user_id = :userId AND platform = :platform ORDER BY published_at DESC")
            .bind("userId", userId)
            .bind("platform", platform)
            .map { row, _ -> mapRowToFeedItem(row) }
            .all()
            .collectList()
            .awaitSingle()
    }

    // BUG-0049: Bulk delete without ownership verification — any user can delete any items by ID (CWE-639, CVSS 6.5, TRICKY, Tier 6)
    suspend fun bulkDeleteItems(itemIds: List<Long>): Long {
        val idList = itemIds.joinToString(",")
        val sql = "DELETE FROM feed_items WHERE id IN ($idList)"
        return databaseClient.sql(sql)
            .fetch()
            .rowsUpdated()
            .awaitSingle()
    }

    // BUG-0050: N+1 query pattern — fetches user for each feed item individually (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
    suspend fun enrichFeedItems(items: List<FeedItem>): List<Map<String, Any?>> {
        return items.map { item ->
            val user = databaseClient.sql("SELECT * FROM users WHERE id = :id")
                .bind("id", item.userId)
                .map { row, _ -> row.get("username", String::class.java) }
                .first()
                .awaitFirstOrNull()

            mapOf(
                "item" to item,
                "ownerUsername" to user
            )
        }
    }

    // BUG-0051: Raw SQL with string interpolation for date range filter (CWE-89, CVSS 8.6, CRITICAL, Tier 1)
    suspend fun findByDateRange(userId: Long, fromDate: String, toDate: String): List<FeedItem> {
        val sql = "SELECT * FROM feed_items WHERE user_id = $userId AND published_at BETWEEN '$fromDate' AND '$toDate'"
        return databaseClient.sql(sql)
            .map { row, _ -> mapRowToFeedItem(row) }
            .all()
            .collectList()
            .awaitSingle()
    }

    private fun mapRowToFeedItem(row: Row): FeedItem {
        return FeedItem(
            id = row.get("id", java.lang.Long::class.java)?.toLong(),
            userId = row.get("user_id", java.lang.Long::class.java)!!.toLong(),
            platform = row.get("platform", String::class.java)!!,
            platformId = row.get("platform_id", String::class.java)!!,
            title = row.get("title", String::class.java),
            content = row.get("content", String::class.java)!!,
            authorName = row.get("author_name", String::class.java)!!,
            authorUrl = row.get("author_url", String::class.java),
            mediaUrls = row.get("media_urls", String::class.java),
            originalUrl = row.get("original_url", String::class.java)!!,
            publishedAt = row.get("published_at", java.time.Instant::class.java)!!,
            fetchedAt = row.get("fetched_at", java.time.Instant::class.java)!!,
            moderationStatus = row.get("moderation_status", String::class.java)!!,
            metadata = row.get("metadata", String::class.java)
        )
    }
}
