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
import com.stan.services.EmailService
import org.koin.ktor.ext.inject
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import java.time.LocalDateTime

fun Route.emailRoutes() {
    val emailService by inject<EmailService>()

    route("/emails") {
        // List email templates
        get("/templates") {
            val templates = transaction {
                EmailTemplates.selectAll().map { row ->
                    mapOf(
                        "id" to row[EmailTemplates.id].value,
                        "name" to row[EmailTemplates.name],
                        "subject" to row[EmailTemplates.subject],
                        "body" to row[EmailTemplates.body],
                        "created_by" to row[EmailTemplates.createdBy],
                        "created_at" to row[EmailTemplates.createdAt].toString()
                    )
                }
            }
            call.respond(templates)
        }

        // Create email template
        post("/templates") {
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.payload?.getClaim("userId")?.asInt() ?: 0
            val body = call.receive<Map<String, String>>()

            // BUG-0072: Template body not sanitized — allows SSTI payloads to be stored (CWE-1336, CVSS 9.8, CRITICAL, Tier 1)
            val templateId = transaction {
                EmailTemplates.insert {
                    it[name] = body["name"] ?: "untitled"
                    it[subject] = body["subject"] ?: ""
                    it[EmailTemplates.body] = body["body"] ?: ""
                    it[createdBy] = userId
                    it[createdAt] = LocalDateTime.now()
                } get EmailTemplates.id
            }

            call.respond(HttpStatusCode.Created, mapOf("id" to templateId.value))
        }

        // Update template
        put("/templates/{id}") {
            val templateId = call.parameters["id"]?.toIntOrNull()
                ?: return@put call.respond(HttpStatusCode.BadRequest)

            val body = call.receive<Map<String, String>>()

            // BUG-0073: No authorization check — any user can update any template (CWE-862, CVSS 6.5, MEDIUM, Tier 3)
            transaction {
                EmailTemplates.update({ EmailTemplates.id eq templateId }) {
                    body["name"]?.let { v -> it[name] = v }
                    body["subject"]?.let { v -> it[subject] = v }
                    body["body"]?.let { v -> it[EmailTemplates.body] = v }
                }
            }

            call.respond(mapOf("message" to "Template updated"))
        }

        // Send email
        post("/send") {
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.payload?.getClaim("userId")?.asInt() ?: 0
            val request = call.receive<EmailSendRequest>()

            var subject = request.subject ?: ""
            var body = request.body ?: ""

            // If template is specified, load and merge variables
            if (request.templateId != null) {
                val template = transaction {
                    EmailTemplates.select { EmailTemplates.id eq request.templateId }.firstOrNull()
                }

                if (template != null) {
                    subject = template[EmailTemplates.subject]
                    body = template[EmailTemplates.body]

                    // BUG-0074: Template variable interpolation uses string replacement — SSTI via variables (CWE-1336, CVSS 9.8, CRITICAL, Tier 1)
                    for ((key, value) in request.variables) {
                        subject = subject.replace("\${$key}", value)
                        body = body.replace("\${$key}", value)
                    }
                }
            }

            // BUG-0075: Email header injection via CC field — newlines allow header manipulation (CWE-93, CVSS 7.5, TRICKY, Tier 5)
            val cc = request.cc
            val bcc = request.bcc

            // BUG-0076: Email header injection via Reply-To field (CWE-93, CVSS 7.5, TRICKY, Tier 5)
            val replyTo = request.replyTo

            try {
                emailService.sendEmail(
                    to = request.to,
                    subject = subject,
                    body = body,
                    cc = cc,
                    bcc = bcc,
                    replyTo = replyTo
                )

                // Log sent email
                transaction {
                    SentEmails.insert {
                        it[toAddress] = request.to
                        it[fromAddress] = emailService.fromAddress
                        it[SentEmails.subject] = subject
                        it[SentEmails.body] = body
                        it[templateId] = request.templateId
                        it[contactId] = request.contactId
                        it[dealId] = request.dealId
                        it[SentEmails.userId] = userId
                        it[status] = "sent"
                        it[sentAt] = LocalDateTime.now()
                    }
                }

                call.respond(mapOf("message" to "Email sent successfully"))
            } catch (e: Exception) {
                // BUG-0077: Email send error exposes SMTP server details (CWE-209, CVSS 4.3, MEDIUM, Tier 3)
                call.respond(HttpStatusCode.InternalServerError, mapOf(
                    "error" to "Failed to send email",
                    "details" to e.message,
                    "smtp_host" to emailService.smtpHost,
                    "smtp_port" to emailService.smtpPort
                ))
            }
        }

        // Bulk email send
        post("/bulk-send") {
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.payload?.getClaim("userId")?.asInt() ?: 0

            val body = call.receive<Map<String, Any>>()
            @Suppress("UNCHECKED_CAST")
            val contactIds = (body["contact_ids"] as? List<Int>) ?: emptyList()
            val templateId = (body["template_id"] as? Number)?.toInt()
            @Suppress("UNCHECKED_CAST")
            val variables = (body["variables"] as? Map<String, String>) ?: emptyMap()

            if (templateId == null) {
                call.respond(HttpStatusCode.BadRequest, mapOf("error" to "template_id required"))
                return@post
            }

            // BUG-0078: No rate limiting on bulk email — can be used for spam (CWE-799, CVSS 4.3, LOW, Tier 4)
            // BUG-0079: GlobalScope launch leaks coroutines on server shutdown (CWE-404, CVSS 3.7, BEST_PRACTICE, Tier 4)
            GlobalScope.launch {
                for (contactId in contactIds) {
                    val contact = transaction {
                        Contacts.select { Contacts.id eq contactId }.firstOrNull()
                    } ?: continue

                    val template = transaction {
                        EmailTemplates.select { EmailTemplates.id eq templateId }.firstOrNull()
                    } ?: continue

                    var emailSubject = template[EmailTemplates.subject]
                    var emailBody = template[EmailTemplates.body]

                    val mergedVars = variables + mapOf(
                        "contact_name" to "${contact[Contacts.firstName]} ${contact[Contacts.lastName]}",
                        "contact_email" to contact[Contacts.email],
                        "company_name" to (contact[Contacts.company] ?: "")
                    )

                    for ((key, value) in mergedVars) {
                        emailSubject = emailSubject.replace("\${$key}", value)
                        emailBody = emailBody.replace("\${$key}", value)
                    }

                    try {
                        emailService.sendEmail(
                            to = contact[Contacts.email],
                            subject = emailSubject,
                            body = emailBody
                        )

                        transaction {
                            SentEmails.insert {
                                it[toAddress] = contact[Contacts.email]
                                it[fromAddress] = emailService.fromAddress
                                it[SentEmails.subject] = emailSubject
                                it[SentEmails.body] = emailBody
                                it[SentEmails.templateId] = templateId
                                it[SentEmails.contactId] = contactId
                                it[SentEmails.userId] = userId
                                it[status] = "sent"
                                it[sentAt] = LocalDateTime.now()
                            }
                        }
                    } catch (e: Exception) {
                        // Silently continue on failure
                    }
                }
            }

            call.respond(mapOf("message" to "Bulk send initiated", "count" to contactIds.size))
        }

        // Email history
        get("/history") {
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.payload?.getClaim("userId")?.asInt() ?: 0

            // BUG-0080: All users can see all sent emails — no ownership filter (CWE-862, CVSS 4.3, MEDIUM, Tier 3)
            val emails = transaction {
                SentEmails.selectAll().orderBy(SentEmails.sentAt, SortOrder.DESC).limit(100).map { row ->
                    mapOf(
                        "id" to row[SentEmails.id].value,
                        "to" to row[SentEmails.toAddress],
                        "from" to row[SentEmails.fromAddress],
                        "subject" to row[SentEmails.subject],
                        "status" to row[SentEmails.status],
                        "contact_id" to row[SentEmails.contactId],
                        "deal_id" to row[SentEmails.dealId],
                        "sent_at" to row[SentEmails.sentAt].toString()
                    )
                }
            }

            call.respond(emails)
        }

        // Preview template with variables
        post("/preview") {
            val request = call.receive<EmailSendRequest>()

            if (request.templateId == null) {
                call.respond(HttpStatusCode.BadRequest, mapOf("error" to "templateId required"))
                return@post
            }

            val template = transaction {
                EmailTemplates.select { EmailTemplates.id eq request.templateId }.firstOrNull()
            } ?: return@post call.respond(HttpStatusCode.NotFound)

            var previewSubject = template[EmailTemplates.subject]
            var previewBody = template[EmailTemplates.body]

            // RH-004: Template preview uses the same replacement logic but output is only shown to the user who requested it — however the real vulnerability is in the send path (BUG-0074), not here
            for ((key, value) in request.variables) {
                previewSubject = previewSubject.replace("\${$key}", value)
                previewBody = previewBody.replace("\${$key}", value)
            }

            call.respond(mapOf("subject" to previewSubject, "body" to previewBody))
        }
    }
}
