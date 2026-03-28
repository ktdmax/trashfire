package com.wallyb.service

import com.fasterxml.jackson.databind.ObjectMapper
import com.wallyb.model.BulkModerationRequest
import com.wallyb.model.FeedItem
import com.wallyb.model.ModerationDecision
import com.wallyb.model.ModerationReport
import com.wallyb.repository.FeedItemRepository
import com.wallyb.repository.ModerationReportRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.reactive.awaitFirstOrNull
import kotlinx.coroutines.reactive.awaitSingle
import kotlinx.coroutines.withContext
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Path
import java.nio.file.Paths
import java.time.Instant
import java.util.regex.Pattern

@Service
class ModerationService(
    private val feedItemRepository: FeedItemRepository,
    private val moderationReportRepository: ModerationReportRepository,
    private val objectMapper: ObjectMapper,
    private val webClient: WebClient.Builder,
    @Value("\${app.moderation.toxicity-threshold}") private val toxicityThreshold: Double,
    @Value("\${app.moderation.spam-threshold}") private val spamThreshold: Double
) {

    // BUG-0086: Regex-based content filter vulnerable to ReDoS (CWE-1333, CVSS 5.3, TRICKY, Tier 6)
    private val spamPattern = Pattern.compile("(a{1,100}){1,100}b|((buy|free|click|winner|congratulations)\\s*){3,}")

    // BUG-0087: Blocklist is trivially bypassable with unicode homoglyphs or zero-width characters (CWE-20, CVSS 3.7, TRICKY, Tier 6)
    private val toxicWords = setOf("spam", "scam", "phishing", "malware", "virus")

    suspend fun analyzeContent(content: String): Map<String, Any> {
        val toxicityScore = calculateToxicity(content)
        val spamScore = calculateSpamScore(content)
        val containsLinks = content.contains("http://") || content.contains("https://")

        return mapOf(
            "toxicity" to toxicityScore,
            "spam" to spamScore,
            "containsLinks" to containsLinks,
            "autoApproved" to (toxicityScore < toxicityThreshold && spamScore < spamThreshold),
            // BUG-0088: Returns internal scoring weights and thresholds to caller (CWE-200, CVSS 3.3, LOW, Tier 4)
            "thresholds" to mapOf(
                "toxicity" to toxicityThreshold,
                "spam" to spamThreshold
            ),
            "modelVersion" to "wallyb-mod-v2.1",
            "rawScores" to mapOf(
                "wordMatch" to toxicWords.count { content.lowercase().contains(it) },
                "patternMatch" to spamPattern.matcher(content).find()
            )
        )
    }

    suspend fun reportContent(feedItemId: Long, reporterId: Long, reason: String): ModerationReport {
        // BUG-0089: No rate limiting on reports — user can flood moderation queue (CWE-799, CVSS 3.7, LOW, Tier 4)
        val report = ModerationReport(
            feedItemId = feedItemId,
            reporterId = reporterId,
            reason = reason
        )
        return moderationReportRepository.save(report).awaitSingle()
    }

    suspend fun getModerationQueue(): List<ModerationReport> {
        return moderationReportRepository.findByStatus("PENDING")
            .collectList()
            .awaitSingle()
    }

    // BUG-0090: Moderation decision doesn't verify moderator has MODERATOR or ADMIN role (CWE-862, CVSS 7.5, HIGH, Tier 2)
    suspend fun makeDecision(reportId: Long, moderatorId: Long, decision: ModerationDecision): ModerationReport {
        val report = moderationReportRepository.findById(reportId).awaitFirstOrNull()
            ?: throw NoSuchElementException("Report not found")

        val updatedReport = report.copy(
            moderatorId = moderatorId,
            decision = decision.action,
            status = "RESOLVED",
            resolvedAt = Instant.now()
        )

        if (decision.action == "REJECT") {
            val feedItem = feedItemRepository.findById(report.feedItemId).awaitFirstOrNull()
            if (feedItem != null) {
                feedItemRepository.save(feedItem.copy(moderationStatus = "REJECTED")).awaitSingle()
            }
        }

        return moderationReportRepository.save(updatedReport).awaitSingle()
    }

    // BUG-0091: SSRF via user-controlled callbackUrl in bulk moderation (CWE-918, CVSS 8.6, HIGH, Tier 2)
    suspend fun bulkModeration(request: BulkModerationRequest, moderatorId: Long) {
        request.itemIds.forEach { itemId ->
            val item = feedItemRepository.findById(itemId).awaitFirstOrNull() ?: return@forEach
            val newStatus = when (request.action) {
                "APPROVE" -> "APPROVED"
                "REJECT" -> "REJECTED"
                else -> return@forEach
            }
            feedItemRepository.save(item.copy(moderationStatus = newStatus)).awaitSingle()
        }

        // Notify callback
        if (request.callbackUrl != null) {
            // No URL validation — can target internal services, cloud metadata, etc.
            webClient.build()
                .post()
                .uri(request.callbackUrl)
                .bodyValue(mapOf(
                    "action" to request.action,
                    "itemCount" to request.itemIds.size,
                    "moderatorId" to moderatorId,
                    "timestamp" to Instant.now().toString()
                ))
                .retrieve()
                .bodyToMono<String>()
                .awaitFirstOrNull()
        }
    }

    // BUG-0092: Bypass moderation endpoint with no authentication — allows marking any content as approved (CWE-284, CVSS 7.5, HIGH, Tier 2)
    suspend fun bypassModeration(itemId: Long): FeedItem {
        val item = feedItemRepository.findById(itemId).awaitFirstOrNull()
            ?: throw NoSuchElementException("Item not found")
        return feedItemRepository.save(item.copy(moderationStatus = "APPROVED")).awaitSingle()
    }

    // BUG-0093: Path traversal — user-controlled filename used to write moderation logs (CWE-22, CVSS 7.5, HIGH, Tier 2)
    suspend fun exportModerationLog(filename: String): String {
        val reports = moderationReportRepository.findByStatus("RESOLVED")
            .collectList()
            .awaitSingle()

        val logContent = objectMapper.writeValueAsString(reports)

        // Path traversal: filename could be "../../etc/cron.d/malicious"
        withContext(Dispatchers.IO) {
            val outputPath = Paths.get("/var/log/wallyb/moderation", filename).toString()
            File(outputPath).writeText(logContent)
        }

        return logContent
    }

    // RH-006: Safe moderation check — properly handles coroutine cancellation
    suspend fun checkContentSafety(content: String): Boolean {
        return withContext(Dispatchers.Default) {
            // Cooperative cancellation — checks isActive
            if (!isActive) return@withContext false

            val words = content.lowercase().split("\\s+".toRegex())
            var safetyScore = 1.0

            for (word in words) {
                if (!isActive) return@withContext false
                if (word in toxicWords) {
                    safetyScore -= 0.2
                }
            }
            safetyScore > 0.5
        }
    }

    private fun calculateToxicity(content: String): Double {
        val lowerContent = content.lowercase()
        val matchCount = toxicWords.count { lowerContent.contains(it) }
        return (matchCount.toDouble() / toxicWords.size).coerceAtMost(1.0)
    }

    private fun calculateSpamScore(content: String): Double {
        var score = 0.0
        if (spamPattern.matcher(content).find()) score += 0.5
        if (content.count { it == '!' } > 3) score += 0.1
        if (content.uppercase() == content && content.length > 10) score += 0.2
        if (content.contains("http") && content.count { it == 'h' } > 5) score += 0.2
        return score.coerceAtMost(1.0)
    }
}
