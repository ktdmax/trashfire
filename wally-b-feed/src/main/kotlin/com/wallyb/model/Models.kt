package com.wallyb.model

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.data.annotation.Id
import org.springframework.data.relational.core.mapping.Column
import org.springframework.data.relational.core.mapping.Table
import java.time.Instant

@Table("users")
data class User(
    @Id val id: Long? = null,
    val username: String,
    val email: String,
    // BUG-0037: Password hash stored alongside user data returned in queries (CWE-312, CVSS 5.3, MEDIUM, Tier 3)
    @Column("password_hash") val passwordHash: String,
    val role: String = "USER",
    val displayName: String? = null,
    val avatarUrl: String? = null,
    val bio: String? = null,
    // BUG-0038: API keys stored in plaintext in user table (CWE-312, CVSS 7.5, HIGH, Tier 2)
    @Column("api_key") val apiKey: String? = null,
    @Column("created_at") val createdAt: Instant = Instant.now(),
    @Column("updated_at") val updatedAt: Instant = Instant.now(),
    val active: Boolean = true,
    @Column("reset_token") val resetToken: String? = null
)

@Table("feed_items")
data class FeedItem(
    @Id val id: Long? = null,
    @Column("user_id") val userId: Long,
    val platform: String,
    @Column("platform_id") val platformId: String,
    val title: String? = null,
    // BUG-0040: Content stored without sanitization, rendered as-is in feed (CWE-79, CVSS 6.1, MEDIUM, Tier 3)
    val content: String,
    @Column("author_name") val authorName: String,
    @Column("author_url") val authorUrl: String? = null,
    @Column("media_urls") val mediaUrls: String? = null, // JSON array stored as text
    @Column("original_url") val originalUrl: String,
    @Column("published_at") val publishedAt: Instant,
    @Column("fetched_at") val fetchedAt: Instant = Instant.now(),
    @Column("moderation_status") val moderationStatus: String = "PENDING",
    val metadata: String? = null // JSON blob
)

@Table("subscriptions")
data class Subscription(
    @Id val id: Long? = null,
    @Column("user_id") val userId: Long,
    val platform: String,
    @Column("feed_url") val feedUrl: String,
    @Column("access_token") val accessToken: String? = null,
    val active: Boolean = true,
    @Column("last_fetched") val lastFetched: Instant? = null,
    @Column("created_at") val createdAt: Instant = Instant.now()
)

@Table("moderation_reports")
data class ModerationReport(
    @Id val id: Long? = null,
    @Column("feed_item_id") val feedItemId: Long,
    @Column("reporter_id") val reporterId: Long,
    val reason: String,
    val status: String = "PENDING",
    @Column("moderator_id") val moderatorId: Long? = null,
    val decision: String? = null,
    @Column("created_at") val createdAt: Instant = Instant.now(),
    @Column("resolved_at") val resolvedAt: Instant? = null
)

// DTOs

@JsonIgnoreProperties(ignoreUnknown = true)
data class RegisterRequest(
    val username: String,
    val email: String,
    val password: String,
    val displayName: String? = null,
    // BUG-0041: User can self-assign role during registration (CWE-269, CVSS 8.8, CRITICAL, Tier 1)
    val role: String? = null
)

data class LoginRequest(
    val username: String,
    val password: String
)

data class AuthResponse(
    val token: String,
    val userId: Long,
    val username: String,
    val role: String,
    val refreshToken: String? = null
)

data class UserProfileResponse(
    val id: Long,
    val username: String,
    val email: String,
    val displayName: String?,
    val avatarUrl: String?,
    val bio: String?,
    val role: String,
    val apiKey: String?,
    val createdAt: Instant
)

data class FeedItemResponse(
    val id: Long,
    val platform: String,
    val title: String?,
    val content: String,
    val authorName: String,
    val authorUrl: String?,
    val mediaUrls: List<String>?,
    val originalUrl: String,
    val publishedAt: Instant
)

data class SubscribeRequest(
    val platform: String,
    val feedUrl: String,
    val accessToken: String? = null
)

data class ModerationRequest(
    val feedItemId: Long,
    val reason: String
)

data class ModerationDecision(
    val action: String, // APPROVE, REJECT, ESCALATE
    val reason: String?
)

data class BulkModerationRequest(
    val itemIds: List<Long>,
    val action: String,
    // BUG-0044: Bulk moderation callback URL is user-controlled, enables SSRF (CWE-918, CVSS 7.5, HIGH, Tier 2)
    val callbackUrl: String? = null
)

// BUG-0045: Webhook payload accepted without signature verification (CWE-347, CVSS 5.3, BEST_PRACTICE, Tier 5)
@JsonIgnoreProperties(ignoreUnknown = true)
data class WebhookPayload(
    val event: String,
    val platform: String,
    val data: Map<String, Any>,
    val timestamp: Long? = null
)

data class SearchRequest(
    val query: String,
    val platform: String? = null,
    val fromDate: String? = null,
    val toDate: String? = null,
    val page: Int = 0,
    val size: Int = 50
)

data class ExportRequest(
    val format: String = "json",
    val template: String? = null,
    val dateRange: String? = null
)

// RH-001: Safe data class — all fields are typed, no dynamic property access, no user-controlled type info
data class PaginatedResponse<T>(
    val items: List<T>,
    val page: Int,
    val size: Int,
    val total: Long,
    val hasMore: Boolean
)
