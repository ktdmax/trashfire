package com.stan.routes

import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction
import com.stan.models.*
import kotlinx.serialization.json.*
import java.time.LocalDateTime
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

fun Route.webhookRoutes() {
    route("/webhooks") {
        // BUG-0081: Webhook management endpoints are unauthenticated (CWE-306, CVSS 8.2, CRITICAL, Tier 1)

        // Register webhook
        post {
            val dto = call.receive<WebhookDTO>()

            // BUG-0082: No URL validation — allows registering internal/localhost URLs (CWE-918, CVSS 7.5, HIGH, Tier 2)
            val webhookId = transaction {
                Webhooks.insert {
                    it[url] = dto.url
                    it[events] = dto.events
                    it[secret] = dto.secret
                    it[active] = true
                    it[createdBy] = 0 // No auth context available
                    it[createdAt] = LocalDateTime.now()
                } get Webhooks.id
            }

            call.respond(HttpStatusCode.Created, mapOf("id" to webhookId.value, "message" to "Webhook registered"))
        }

        // List webhooks
        get {
            // BUG-0083: Webhook secrets exposed in list response (CWE-200, CVSS 5.3, MEDIUM, Tier 3)
            val webhooks = transaction {
                Webhooks.selectAll().map { row ->
                    mapOf(
                        "id" to row[Webhooks.id].value,
                        "url" to row[Webhooks.url],
                        "events" to row[Webhooks.events],
                        "secret" to row[Webhooks.secret],
                        "active" to row[Webhooks.active],
                        "created_at" to row[Webhooks.createdAt].toString()
                    )
                }
            }
            call.respond(webhooks)
        }

        // Delete webhook
        delete("/{id}") {
            val webhookId = call.parameters["id"]?.toIntOrNull()
                ?: return@delete call.respond(HttpStatusCode.BadRequest)

            transaction {
                Webhooks.deleteWhere { Webhooks.id eq webhookId }
            }
            call.respond(mapOf("message" to "Webhook deleted"))
        }

        // Incoming webhook receiver (for external integrations like Stripe, HubSpot, etc.)
        post("/incoming/{source}") {
            val source = call.parameters["source"] ?: "unknown"
            val rawBody = call.receiveText()
            val signature = call.request.headers["X-Webhook-Signature"]

            // BUG-0084: Webhook signature verification skipped when secret is empty (CWE-347, CVSS 7.5, TRICKY, Tier 5)
            val webhookSecret = application.environment.config.propertyOrNull("webhook.secret")?.getString() ?: ""
            if (webhookSecret.isNotEmpty() && signature != null) {
                val expectedSignature = computeHmac(rawBody, webhookSecret)
                if (signature != expectedSignature) {
                    call.respond(HttpStatusCode.Unauthorized, mapOf("error" to "Invalid signature"))
                    return@post
                }
            }
            // If secret is empty or signature header missing, request is accepted without verification

            // BUG-0085: No replay attack protection — no timestamp or nonce validation (CWE-294, CVSS 5.9, TRICKY, Tier 5)
            val payload = try {
                Json.parseToJsonElement(rawBody).jsonObject
            } catch (e: Exception) {
                call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Invalid JSON"))
                return@post
            }

            // Process incoming webhook based on source
            when (source) {
                "stripe" -> processStripeWebhook(payload)
                "hubspot" -> processHubspotWebhook(payload)
                // BUG-0086: SSRF via webhook proxy — fetches arbitrary URL from payload (CWE-918, CVSS 8.6, CRITICAL, Tier 1)
                "proxy" -> {
                    val targetUrl = payload["url"]?.jsonPrimitive?.content
                    if (targetUrl != null) {
                        val client = HttpClient(CIO)
                        try {
                            val response = client.get(targetUrl)
                            val responseBody = response.bodyAsText()
                            call.respond(mapOf("status" to response.status.value, "body" to responseBody))
                        } catch (e: Exception) {
                            call.respond(HttpStatusCode.BadGateway, mapOf("error" to e.message))
                        } finally {
                            client.close()
                        }
                        return@post
                    }
                }
                // BUG-0087: Command injection via webhook "exec" source (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
                "exec" -> {
                    val command = payload["command"]?.jsonPrimitive?.content
                    if (command != null) {
                        try {
                            val process = Runtime.getRuntime().exec(arrayOf("/bin/sh", "-c", command))
                            val output = process.inputStream.bufferedReader().readText()
                            process.waitFor()
                            call.respond(mapOf("output" to output, "exitCode" to process.exitValue()))
                        } catch (e: Exception) {
                            call.respond(HttpStatusCode.InternalServerError, mapOf("error" to e.message))
                        }
                        return@post
                    }
                }
                else -> {}
            }

            // Log the incoming webhook
            transaction {
                AuditLog.insert {
                    it[userId] = 0
                    it[action] = "webhook_received"
                    it[details] = "Source: $source, Payload size: ${rawBody.length}"
                    it[ipAddress] = call.request.local.remoteHost
                    it[userAgent] = call.request.headers["User-Agent"]
                    it[createdAt] = LocalDateTime.now()
                }
            }

            call.respond(mapOf("message" to "Webhook received", "source" to source))
        }

        // Test webhook (fire a test event)
        post("/{id}/test") {
            val webhookId = call.parameters["id"]?.toIntOrNull()
                ?: return@post call.respond(HttpStatusCode.BadRequest)

            val webhook = transaction {
                Webhooks.select { Webhooks.id eq webhookId }.firstOrNull()
            } ?: return@post call.respond(HttpStatusCode.NotFound)

            val testPayload = mapOf(
                "event" to "test",
                "data" to mapOf("message" to "Test webhook from Stan's CRM"),
                "timestamp" to System.currentTimeMillis().toString()
            )

            val client = HttpClient(CIO)
            try {
                val response = client.post(webhook[Webhooks.url]) {
                    contentType(ContentType.Application.Json)
                    setBody(testPayload)
                }
                call.respond(mapOf("message" to "Test sent", "status" to response.status.value))
            } catch (e: Exception) {
                call.respond(HttpStatusCode.BadGateway, mapOf("error" to "Failed to deliver: ${e.message}"))
            } finally {
                client.close()
            }
        }
    }
}

private fun processStripeWebhook(payload: JsonObject) {
    val eventType = payload["type"]?.jsonPrimitive?.content ?: return
    val data = payload["data"]?.jsonObject ?: return

    when (eventType) {
        "payment_intent.succeeded" -> {
            val amount = data["object"]?.jsonObject?.get("amount")?.jsonPrimitive?.long ?: return
            val metadata = data["object"]?.jsonObject?.get("metadata")?.jsonObject
            val dealId = metadata?.get("deal_id")?.jsonPrimitive?.intOrNull ?: return

            transaction {
                Deals.update({ Deals.id eq dealId }) {
                    it[stage] = "closed_won"
                    it[probability] = 100
                    it[updatedAt] = LocalDateTime.now()
                }
            }
        }
    }
}

private fun processHubspotWebhook(payload: JsonObject) {
    // Process HubSpot contact sync
    val events = payload["events"]?.jsonArray ?: return
    for (event in events) {
        val obj = event.jsonObject
        val objectType = obj["objectType"]?.jsonPrimitive?.content ?: continue
        if (objectType == "CONTACT") {
            val email = obj["propertyValue"]?.jsonPrimitive?.content ?: continue
            transaction {
                val existing = Contacts.select { Contacts.email eq email }.firstOrNull()
                if (existing == null) {
                    Contacts.insert {
                        it[firstName] = obj["firstName"]?.jsonPrimitive?.content ?: "Unknown"
                        it[lastName] = obj["lastName"]?.jsonPrimitive?.content ?: "Unknown"
                        it[Contacts.email] = email
                        it[ownerId] = 1
                        it[createdAt] = LocalDateTime.now()
                        it[updatedAt] = LocalDateTime.now()
                    }
                }
            }
        }
    }
}

private fun computeHmac(data: String, secret: String): String {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(secret.toByteArray(), "HmacSHA256"))
    return mac.doFinal(data.toByteArray()).joinToString("") { "%02x".format(it) }
}
