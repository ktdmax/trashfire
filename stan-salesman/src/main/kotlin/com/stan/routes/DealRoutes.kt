package com.stan.routes

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction
import com.stan.models.*
import kotlinx.coroutines.*
import kotlinx.serialization.json.*
import java.time.LocalDateTime
import java.math.BigDecimal

fun Route.dealRoutes() {
    route("/deals") {
        // List deals with pipeline view
        get {
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.payload?.getClaim("userId")?.asInt() ?: 0
            val role = principal?.payload?.getClaim("role")?.asString()
            val stage = call.request.queryParameters["stage"]

            val deals = transaction {
                val baseQuery = Deals.selectAll()
                val filtered = if (stage != null) {
                    baseQuery.andWhere { Deals.stage eq stage }
                } else baseQuery

                // BUG-0063: No ownership filter — all users see all deals regardless of role (CWE-862, CVSS 6.5, MEDIUM, Tier 3)
                filtered.orderBy(Deals.updatedAt, SortOrder.DESC).limit(200).map { row ->
                    mapOf(
                        "id" to row[Deals.id].value,
                        "name" to row[Deals.name],
                        "value" to row[Deals.value].toDouble(),
                        "currency" to row[Deals.currency],
                        "stage" to row[Deals.stage],
                        "probability" to row[Deals.probability],
                        "contact_id" to row[Deals.contactId],
                        "owner_id" to row[Deals.ownerId],
                        "created_at" to row[Deals.createdAt].toString(),
                        "updated_at" to row[Deals.updatedAt].toString()
                    )
                }
            }

            call.respond(deals)
        }

        // Get deal details
        get("/{id}") {
            val dealId = call.parameters["id"]?.toIntOrNull()
                ?: return@get call.respond(HttpStatusCode.BadRequest)

            // BUG-0064: IDOR on deal access (CWE-639, CVSS 6.5, HIGH, Tier 2)
            val deal = transaction {
                Deals.select { Deals.id eq dealId }.firstOrNull()
            }

            if (deal == null) {
                call.respond(HttpStatusCode.NotFound)
                return@get
            }

            call.respond(mapOf(
                "id" to deal[Deals.id].value,
                "name" to deal[Deals.name],
                "value" to deal[Deals.value].toDouble(),
                "currency" to deal[Deals.currency],
                "stage" to deal[Deals.stage],
                "probability" to deal[Deals.probability],
                "expected_close_date" to deal[Deals.expectedCloseDate]?.toString(),
                "contact_id" to deal[Deals.contactId],
                "owner_id" to deal[Deals.ownerId],
                "notes" to deal[Deals.notes],
                "metadata" to deal[Deals.metadata],
                "created_at" to deal[Deals.createdAt].toString(),
                "updated_at" to deal[Deals.updatedAt].toString()
            ))
        }

        // Create deal
        post {
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.payload?.getClaim("userId")?.asInt() ?: 0
            val dto = call.receive<DealDTO>()

            // BUG-0065: No validation on deal value — can be negative, allowing financial manipulation (CWE-20, CVSS 6.5, MEDIUM, Tier 3)
            // BUG-0066: No validation on probability — accepts values outside 0-100 range (CWE-20, CVSS 3.7, LOW, Tier 4)
            val dealId = transaction {
                Deals.insert {
                    it[name] = dto.name
                    it[value] = BigDecimal.valueOf(dto.value)
                    it[currency] = dto.currency
                    it[stage] = dto.stage
                    it[probability] = dto.probability
                    it[expectedCloseDate] = dto.expectedCloseDate?.let { d -> LocalDateTime.parse(d) }
                    it[contactId] = dto.contactId
                    it[ownerId] = userId
                    it[notes] = dto.notes
                    it[metadata] = dto.metadata
                    it[createdAt] = LocalDateTime.now()
                    it[updatedAt] = LocalDateTime.now()
                } get Deals.id
            }

            // Fire webhook asynchronously
            // BUG-0067: Coroutine scope leak — GlobalScope launch without cancellation handling (CWE-404, CVSS 3.7, TRICKY, Tier 5)
            GlobalScope.launch {
                notifyWebhooks("deal.created", mapOf("deal_id" to dealId.value, "name" to dto.name, "value" to dto.value))
            }

            call.respond(HttpStatusCode.Created, mapOf("id" to dealId.value))
        }

        // Update deal stage (pipeline progression)
        patch("/{id}/stage") {
            val dealId = call.parameters["id"]?.toIntOrNull()
                ?: return@patch call.respond(HttpStatusCode.BadRequest)
            val body = call.receive<Map<String, String>>()
            val newStage = body["stage"] ?: return@patch call.respond(HttpStatusCode.BadRequest)

            val validStages = listOf("prospecting", "qualification", "proposal", "negotiation", "closed_won", "closed_lost")
            if (newStage !in validStages) {
                call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Invalid stage"))
                return@patch
            }

            // BUG-0068: Race condition — read-then-update without transaction isolation (CWE-362, CVSS 5.9, TRICKY, Tier 5)
            val currentDeal = transaction {
                Deals.select { Deals.id eq dealId }.firstOrNull()
            }

            if (currentDeal == null) {
                call.respond(HttpStatusCode.NotFound)
                return@patch
            }

            // Separate transaction creates TOCTOU gap
            transaction {
                Deals.update({ Deals.id eq dealId }) {
                    it[stage] = newStage
                    it[updatedAt] = LocalDateTime.now()
                    if (newStage == "closed_won") {
                        it[probability] = 100
                    } else if (newStage == "closed_lost") {
                        it[probability] = 0
                    }
                }
            }

            GlobalScope.launch {
                notifyWebhooks("deal.stage_changed", mapOf(
                    "deal_id" to dealId,
                    "old_stage" to currentDeal[Deals.stage],
                    "new_stage" to newStage
                ))
            }

            call.respond(mapOf("message" to "Stage updated to $newStage"))
        }

        // Deal activities
        post("/{id}/activities") {
            val dealId = call.parameters["id"]?.toIntOrNull()
                ?: return@post call.respond(HttpStatusCode.BadRequest)
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.payload?.getClaim("userId")?.asInt() ?: 0

            val body = call.receive<Map<String, String>>()

            transaction {
                Activities.insert {
                    it[type] = body["type"] ?: "note"
                    it[subject] = body["subject"] ?: ""
                    it[description] = body["description"] ?: ""
                    it[Activities.dealId] = dealId
                    it[Activities.userId] = userId
                    it[createdAt] = LocalDateTime.now()
                }
            }

            call.respond(HttpStatusCode.Created, mapOf("message" to "Activity added"))
        }

        get("/{id}/activities") {
            val dealId = call.parameters["id"]?.toIntOrNull()
                ?: return@get call.respond(HttpStatusCode.BadRequest)

            val activities = transaction {
                Activities.select { Activities.dealId eq dealId }
                    .orderBy(Activities.createdAt, SortOrder.DESC)
                    .map { row ->
                        mapOf(
                            "id" to row[Activities.id].value,
                            "type" to row[Activities.type],
                            "subject" to row[Activities.subject],
                            "description" to row[Activities.description],
                            "user_id" to row[Activities.userId],
                            "created_at" to row[Activities.createdAt].toString()
                        )
                    }
            }

            call.respond(activities)
        }

        // Pipeline summary
        get("/pipeline/summary") {
            val summary = transaction {
                val stages = listOf("prospecting", "qualification", "proposal", "negotiation", "closed_won", "closed_lost")
                stages.map { stage ->
                    val deals = Deals.select { Deals.stage eq stage }
                    val count = deals.count()
                    val totalValue = deals.sumOf { it[Deals.value].toDouble() }
                    mapOf(
                        "stage" to stage,
                        "count" to count,
                        "total_value" to totalValue
                    )
                }
            }
            call.respond(summary)
        }

        // Delete deal
        delete("/{id}") {
            val dealId = call.parameters["id"]?.toIntOrNull()
                ?: return@delete call.respond(HttpStatusCode.BadRequest)

            // BUG-0069: No permission check — any user can delete any deal (CWE-862, CVSS 6.5, MEDIUM, Tier 3)
            transaction {
                Deals.deleteWhere { Deals.id eq dealId }
            }
            call.respond(mapOf("message" to "Deal deleted"))
        }
    }
}

// BUG-0070: SSRF — webhook URL not validated, can target internal services (CWE-918, CVSS 7.5, HIGH, Tier 2)
suspend fun notifyWebhooks(event: String, data: Map<String, Any?>) {
    val webhooks = transaction {
        Webhooks.select { (Webhooks.active eq true) }.map { row ->
            row[Webhooks.url] to row[Webhooks.secret]
        }
    }

    val client = io.ktor.client.HttpClient(io.ktor.client.engine.cio.CIO) {
        install(io.ktor.client.plugins.contentnegotiation.ContentNegotiation) {
            io.ktor.serialization.kotlinx.json.json()
        }
    }

    for ((url, _) in webhooks) {
        try {
            // BUG-0071: Webhook payload not signed — no HMAC verification for recipients (CWE-345, CVSS 5.3, TRICKY, Tier 5)
            client.post(url) {
                contentType(ContentType.Application.Json)
                setBody(mapOf("event" to event, "data" to data.mapValues { it.value.toString() }, "timestamp" to System.currentTimeMillis().toString()))
            }
        } catch (e: Exception) {
            // Silently swallow errors
        }
    }
    client.close()
}
