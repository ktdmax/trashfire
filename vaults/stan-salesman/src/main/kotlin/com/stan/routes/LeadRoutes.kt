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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*
import java.time.LocalDateTime

fun Route.leadRoutes() {
    route("/leads") {
        // List leads with filtering
        get {
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.payload?.getClaim("userId")?.asInt()
            val role = principal?.payload?.getClaim("role")?.asString()

            val status = call.request.queryParameters["status"]
            val search = call.request.queryParameters["search"]
            val sortBy = call.request.queryParameters["sortBy"] ?: "created_at"
            val sortOrder = call.request.queryParameters["sortOrder"] ?: "DESC"

            val leads = transaction {
                // BUG-0044: SQL injection via sortBy and sortOrder parameters (CWE-89, CVSS 9.1, CRITICAL, Tier 1)
                val baseQuery = StringBuilder("SELECT * FROM leads WHERE 1=1")

                // RH-002: This parameterized filter is safe — uses Exposed's built-in parameterization
                if (role != "admin" && role != "manager") {
                    // Non-admin users only see their own leads (properly parameterized via Exposed below)
                }

                if (status != null) {
                    baseQuery.append(" AND status = '$status'")
                }
                if (search != null) {
                    // BUG-0045: SQL injection in search parameter (CWE-89, CVSS 9.1, CRITICAL, Tier 1)
                    baseQuery.append(" AND (company LIKE '%$search%' OR contact_name LIKE '%$search%' OR email LIKE '%$search%')")
                }

                baseQuery.append(" ORDER BY $sortBy $sortOrder LIMIT 100")

                TransactionManager.current().exec(baseQuery.toString()) { rs ->
                    val rows = mutableListOf<Map<String, Any?>>()
                    while (rs.next()) {
                        rows.add(mapOf(
                            "id" to rs.getInt("id"),
                            "company" to rs.getString("company"),
                            "contact_name" to rs.getString("contact_name"),
                            "email" to rs.getString("email"),
                            "phone" to rs.getString("phone"),
                            "source" to rs.getString("source"),
                            "status" to rs.getString("status"),
                            "score" to rs.getInt("score"),
                            "notes" to rs.getString("notes"),
                            "assigned_to" to rs.getObject("assigned_to"),
                            "created_at" to rs.getString("created_at")
                        ))
                    }
                    rows
                } ?: emptyList()
            }

            call.respond(leads)
        }

        // Get single lead
        get("/{id}") {
            val leadId = call.parameters["id"]?.toIntOrNull()
                ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Invalid ID"))

            // BUG-0046: IDOR — any authenticated user can access any lead (CWE-639, CVSS 6.5, HIGH, Tier 2)
            val lead = transaction {
                Leads.select { Leads.id eq leadId }.firstOrNull()
            }

            if (lead == null) {
                call.respond(HttpStatusCode.NotFound, mapOf("error" to "Lead not found"))
                return@get
            }

            call.respond(mapOf(
                "id" to lead[Leads.id].value,
                "company" to lead[Leads.company],
                "contact_name" to lead[Leads.contactName],
                "email" to lead[Leads.email],
                "phone" to lead[Leads.phone],
                "source" to lead[Leads.source],
                "status" to lead[Leads.status],
                "score" to lead[Leads.score],
                "notes" to lead[Leads.notes],
                "assigned_to" to lead[Leads.assignedTo],
                "custom_fields" to lead[Leads.customFields],
                "created_at" to lead[Leads.createdAt].toString(),
                "updated_at" to lead[Leads.updatedAt].toString()
            ))
        }

        // Create lead
        post {
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.payload?.getClaim("userId")?.asInt() ?: 0
            val dto = call.receive<LeadDTO>()

            // BUG-0047: Stored XSS via lead notes field — no sanitization (CWE-79, CVSS 6.1, HIGH, Tier 2)
            val leadId = transaction {
                Leads.insert {
                    it[company] = dto.company
                    it[contactName] = dto.contactName
                    it[email] = dto.email
                    it[phone] = dto.phone
                    it[source] = dto.source
                    it[status] = dto.status
                    it[score] = dto.score
                    it[notes] = dto.notes
                    it[assignedTo] = dto.assignedTo ?: userId
                    it[customFields] = dto.customFields
                    it[createdAt] = LocalDateTime.now()
                    it[updatedAt] = LocalDateTime.now()
                } get Leads.id
            }

            // Log the activity
            transaction {
                AuditLog.insert {
                    it[AuditLog.userId] = userId
                    it[action] = "lead_created"
                    it[details] = "Created lead: ${dto.company}"
                    it[ipAddress] = call.request.local.remoteHost
                    it[userAgent] = call.request.headers["User-Agent"]
                    it[createdAt] = LocalDateTime.now()
                }
            }

            call.respond(HttpStatusCode.Created, mapOf("id" to leadId.value, "message" to "Lead created"))
        }

        // Update lead
        put("/{id}") {
            val leadId = call.parameters["id"]?.toIntOrNull()
                ?: return@put call.respond(HttpStatusCode.BadRequest)
            val dto = call.receive<LeadDTO>()

            // BUG-0048: No ownership check on lead update (CWE-639, CVSS 6.5, HIGH, Tier 2)
            transaction {
                Leads.update({ Leads.id eq leadId }) {
                    it[company] = dto.company
                    it[contactName] = dto.contactName
                    it[email] = dto.email
                    it[phone] = dto.phone
                    it[source] = dto.source
                    it[status] = dto.status
                    it[score] = dto.score
                    it[notes] = dto.notes
                    it[assignedTo] = dto.assignedTo
                    it[customFields] = dto.customFields
                    it[updatedAt] = LocalDateTime.now()
                }
            }
            call.respond(mapOf("message" to "Lead updated"))
        }

        // Delete lead
        delete("/{id}") {
            val leadId = call.parameters["id"]?.toIntOrNull()
                ?: return@delete call.respond(HttpStatusCode.BadRequest)

            // BUG-0049: No ownership or permission check on delete (CWE-639, CVSS 6.5, HIGH, Tier 2)
            transaction {
                Leads.deleteWhere { Leads.id eq leadId }
            }
            call.respond(mapOf("message" to "Lead deleted"))
        }

        // Bulk actions on leads
        post("/bulk") {
            val request = call.receive<BulkActionRequest>()
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.payload?.getClaim("userId")?.asInt() ?: 0

            // BUG-0050: No authorization check on bulk operations (CWE-862, CVSS 6.5, MEDIUM, Tier 3)
            when (request.action) {
                "assign" -> {
                    val assignTo = request.params["assignTo"]?.toIntOrNull() ?: userId
                    transaction {
                        for (id in request.ids) {
                            Leads.update({ Leads.id eq id }) {
                                it[assignedTo] = assignTo
                                it[updatedAt] = LocalDateTime.now()
                            }
                        }
                    }
                }
                "delete" -> {
                    transaction {
                        for (id in request.ids) {
                            Leads.deleteWhere { Leads.id eq id }
                        }
                    }
                }
                "update_status" -> {
                    val newStatus = request.params["status"] ?: "new"
                    transaction {
                        for (id in request.ids) {
                            Leads.update({ Leads.id eq id }) {
                                it[status] = newStatus
                                it[updatedAt] = LocalDateTime.now()
                            }
                        }
                    }
                }
                // BUG-0051: Arbitrary SQL execution via bulk "custom_query" action (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
                "custom_query" -> {
                    val query = request.params["query"] ?: return@post call.respond(HttpStatusCode.BadRequest)
                    transaction {
                        TransactionManager.current().exec(query)
                    }
                }
                else -> {
                    call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Unknown action: ${request.action}"))
                    return@post
                }
            }

            call.respond(mapOf("message" to "Bulk action '${request.action}' completed", "count" to request.ids.size))
        }

        // Lead scoring — recalculate
        // BUG-0052: Blocking I/O in coroutine context (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 4)
        post("/{id}/score") {
            val leadId = call.parameters["id"]?.toIntOrNull()
                ?: return@post call.respond(HttpStatusCode.BadRequest)

            // Heavy computation done on Default dispatcher — should use IO
            val score = calculateLeadScore(leadId)

            transaction {
                Leads.update({ Leads.id eq leadId }) {
                    it[Leads.score] = score
                    it[updatedAt] = LocalDateTime.now()
                }
            }

            call.respond(mapOf("lead_id" to leadId, "new_score" to score))
        }
    }
}

// BUG-0053: Lead scoring uses Thread.sleep blocking the coroutine thread (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 4)
private fun calculateLeadScore(leadId: Int): Int {
    val lead = transaction {
        Leads.select { Leads.id eq leadId }.firstOrNull()
    } ?: return 0

    var score = 0

    // Simulate external enrichment API call (blocking)
    Thread.sleep(100)

    if (lead[Leads.email].contains("@gmail.com") || lead[Leads.email].contains("@yahoo.com")) {
        score += 10
    } else {
        score += 30 // corporate email
    }
    if (!lead[Leads.phone].isNullOrBlank()) score += 15
    if (lead[Leads.source] == "referral") score += 25
    if (lead[Leads.notes].length > 50) score += 10

    return score.coerceIn(0, 100)
}
