package com.wallyb.client

import com.fasterxml.jackson.databind.ObjectMapper
import com.wallyb.model.FeedItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.reactive.awaitFirstOrNull
import kotlinx.coroutines.reactive.awaitSingle
import kotlinx.coroutines.withContext
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono
import org.yaml.snakeyaml.Yaml
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.time.Instant
import javax.xml.parsers.DocumentBuilderFactory

@Component
class PlatformClient(
    private val webClient: WebClient.Builder,
    private val objectMapper: ObjectMapper,
    @Value("\${app.platforms.twitter.api-key}") private val twitterApiKey: String,
    @Value("\${app.platforms.twitter.api-secret}") private val twitterApiSecret: String,
    @Value("\${app.platforms.mastodon.instance-url}") private val mastodonUrl: String,
    @Value("\${app.platforms.mastodon.access-token}") private val mastodonToken: String
) {

    // BUG-0052: SSRF — feedUrl is user-controlled, can target internal services (CWE-918, CVSS 8.6, HIGH, Tier 2)
    suspend fun fetchRssFeed(feedUrl: String, userId: Long): List<FeedItem> {
        // No URL validation — internal IPs, file:// protocol, cloud metadata all accessible
        val response = webClient.build()
            .get()
            .uri(feedUrl)
            .retrieve()
            .bodyToMono<String>()
            .awaitSingle()

        return parseRssFeed(response, userId, feedUrl)
    }

    // BUG-0053: XXE vulnerability — XML parsing without disabling external entities (CWE-611, CVSS 7.5, HIGH, Tier 2)
    private fun parseRssFeed(xml: String, userId: Long, feedUrl: String): List<FeedItem> {
        val factory = DocumentBuilderFactory.newInstance()
        // External entities and DTDs not disabled
        val builder = factory.newDocumentBuilder()
        val document = builder.parse(xml.byteInputStream())

        val items = mutableListOf<FeedItem>()
        val nodeList = document.getElementsByTagName("item")

        for (i in 0 until nodeList.length) {
            val node = nodeList.item(i)
            val children = node.childNodes
            var title = ""
            var content = ""
            var link = ""
            var pubDate = ""
            var author = ""

            for (j in 0 until children.length) {
                when (children.item(j).nodeName) {
                    "title" -> title = children.item(j).textContent
                    "description" -> content = children.item(j).textContent
                    "link" -> link = children.item(j).textContent
                    "pubDate" -> pubDate = children.item(j).textContent
                    "author", "dc:creator" -> author = children.item(j).textContent
                }
            }

            items.add(
                FeedItem(
                    userId = userId,
                    platform = "rss",
                    platformId = link.hashCode().toString(),
                    title = title,
                    content = content,
                    authorName = author.ifEmpty { "Unknown" },
                    originalUrl = link,
                    publishedAt = try { Instant.parse(pubDate) } catch (e: Exception) { Instant.now() }
                )
            )
        }
        return items
    }

    suspend fun fetchTwitterTimeline(accessToken: String, userId: Long): List<FeedItem> {
        val response = webClient.build()
            .get()
            .uri("https://api.twitter.com/2/users/me/timelines/reverse_chronological")
            .header("Authorization", "Bearer $accessToken")
            .retrieve()
            .bodyToMono<Map<String, Any>>()
            .awaitSingle()

        @Suppress("UNCHECKED_CAST")
        val data = response["data"] as? List<Map<String, Any>> ?: emptyList()

        return data.map { tweet ->
            FeedItem(
                userId = userId,
                platform = "twitter",
                platformId = tweet["id"].toString(),
                content = tweet["text"].toString(),
                authorName = tweet["author_id"].toString(),
                originalUrl = "https://twitter.com/i/status/${tweet["id"]}",
                publishedAt = try {
                    Instant.parse(tweet["created_at"].toString())
                } catch (e: Exception) { Instant.now() }
            )
        }
    }

    suspend fun fetchMastodonTimeline(accessToken: String, userId: Long): List<FeedItem> {
        val response = webClient.build()
            .get()
            .uri("$mastodonUrl/api/v1/timelines/home")
            .header("Authorization", "Bearer $accessToken")
            .retrieve()
            .bodyToMono<List<Map<String, Any>>>()
            .awaitSingle()

        return response.map { toot ->
            @Suppress("UNCHECKED_CAST")
            val account = toot["account"] as? Map<String, Any> ?: emptyMap()
            FeedItem(
                userId = userId,
                platform = "mastodon",
                platformId = toot["id"].toString(),
                // BUG-0054: HTML content from Mastodon passed through without sanitization (CWE-79, CVSS 5.3, BEST_PRACTICE, Tier 5)
                content = toot["content"].toString(),
                authorName = account["display_name"]?.toString() ?: "Unknown",
                authorUrl = account["url"]?.toString(),
                originalUrl = toot["url"]?.toString() ?: "",
                publishedAt = try {
                    Instant.parse(toot["created_at"].toString())
                } catch (e: Exception) { Instant.now() }
            )
        }
    }

    // BUG-0055: Command injection via user-controlled URL passed to curl subprocess (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    suspend fun fetchGenericFeed(url: String, userId: Long): String {
        return withContext(Dispatchers.IO) {
            val process = Runtime.getRuntime().exec(arrayOf("curl", "-sL", "--max-time", "30", url))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = reader.readText()
            process.waitFor()
            output
        }
    }

    // BUG-0056: Blocking HTTP call inside coroutine without proper dispatcher (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
    suspend fun verifyWebhookSource(callbackUrl: String): Boolean {
        val url = URL(callbackUrl)
        val connection = url.openConnection() as HttpURLConnection
        connection.requestMethod = "HEAD"
        connection.connectTimeout = 5000
        return connection.responseCode == 200
    }

    // BUG-0057: YAML deserialization of untrusted input using unsafe SnakeYAML constructor (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
    fun parseYamlConfig(yamlContent: String): Map<String, Any> {
        val yaml = Yaml() // Uses default Constructor — allows arbitrary object instantiation
        @Suppress("UNCHECKED_CAST")
        return yaml.load(yamlContent) as Map<String, Any>
    }

    // BUG-0058: Open redirect — user-controlled URL used for redirect without validation (CWE-601, CVSS 5.3, MEDIUM, Tier 3)
    fun buildOAuthCallbackUrl(platform: String, redirectUri: String): String {
        return when (platform) {
            "twitter" -> "https://api.twitter.com/2/oauth2/authorize?redirect_uri=$redirectUri"
            "mastodon" -> "$mastodonUrl/oauth/authorize?redirect_uri=$redirectUri"
            else -> redirectUri
        }
    }

    // RH-004: Safe redirect — URL is validated against allowlist before redirect
    fun buildSafeCallbackUrl(platform: String, state: String): String {
        val allowedCallbacks = mapOf(
            "twitter" to "https://wallyb.example.com/callback/twitter",
            "mastodon" to "https://wallyb.example.com/callback/mastodon"
        )
        val callback = allowedCallbacks[platform] ?: throw IllegalArgumentException("Unknown platform")
        return "$callback?state=$state"
    }
}
