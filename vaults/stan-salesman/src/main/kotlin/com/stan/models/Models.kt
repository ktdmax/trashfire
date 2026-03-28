package com.stan.models

import org.jetbrains.exposed.dao.id.IntIdTable
import org.jetbrains.exposed.sql.javatime.datetime
import kotlinx.serialization.Serializable
import kotlinx.serialization.Contextual
import java.time.LocalDateTime

// --- Database Tables ---

object Users : IntIdTable("users") {
    val email = varchar("email", 255).uniqueIndex()
    val name = varchar("name", 255)
    val passwordHash_ = varchar("password_hash", 255)
    val role = varchar("role", 50).default("sales_rep")
    val active = bool("active").default(true)
    val resetTokenCol = varchar("reset_token", 255).nullable()
    val resetTokenExpiry = datetime("reset_token_expiry").nullable()
    val createdAt = datetime("created_at")
}

object Leads : IntIdTable("leads") {
    val company = varchar("company", 255)
    val contactName = varchar("contact_name", 255)
    val email = varchar("email", 255)
    val phone = varchar("phone", 50).nullable()
    val source = varchar("source", 100).default("manual")
    val status = varchar("status", 50).default("new")
    val score = integer("score").default(0)
    val notes = text("notes").default("")
    val assignedTo = integer("assigned_to").nullable()
    val customFields = text("custom_fields").default("{}")
    val createdAt = datetime("created_at")
    val updatedAt = datetime("updated_at")
}

object Contacts : IntIdTable("contacts") {
    val firstName = varchar("first_name", 128)
    val lastName = varchar("last_name", 128)
    val email = varchar("email", 255)
    val phone = varchar("phone", 50).nullable()
    val company = varchar("company", 255).nullable()
    val title = varchar("title", 128).nullable()
    val address = text("address").nullable()
    val notes = text("notes").default("")
    val avatarPath = varchar("avatar_path", 512).nullable()
    val leadId = integer("lead_id").nullable()
    val ownerId = integer("owner_id")
    val createdAt = datetime("created_at")
    val updatedAt = datetime("updated_at")
}

object Deals : IntIdTable("deals") {
    val name = varchar("name", 255)
    val value = decimal("value", 12, 2)
    val currency = varchar("currency", 3).default("USD")
    val stage = varchar("stage", 50).default("prospecting")
    val probability = integer("probability").default(10)
    val expectedCloseDate = datetime("expected_close_date").nullable()
    val contactId = integer("contact_id")
    val ownerId = integer("owner_id")
    val notes = text("notes").default("")
    val metadata = text("metadata").default("{}")
    val createdAt = datetime("created_at")
    val updatedAt = datetime("updated_at")
}

object Activities : IntIdTable("activities") {
    val type = varchar("type", 50)
    val subject = varchar("subject", 255)
    val description = text("description").default("")
    val dealId = integer("deal_id").nullable()
    val contactId = integer("contact_id").nullable()
    val leadId = integer("lead_id").nullable()
    val userId = integer("user_id")
    val scheduledAt = datetime("scheduled_at").nullable()
    val completedAt = datetime("completed_at").nullable()
    val createdAt = datetime("created_at")
}

object EmailTemplates : IntIdTable("email_templates") {
    val name = varchar("name", 100)
    val subject = varchar("subject", 500)
    val body = text("body")
    val createdBy = integer("created_by")
    val createdAt = datetime("created_at")
}

object SentEmails : IntIdTable("sent_emails") {
    val toAddress = varchar("to_address", 255)
    val fromAddress = varchar("from_address", 255)
    val subject = varchar("subject", 500)
    val body = text("body")
    val templateId = integer("template_id").nullable()
    val contactId = integer("contact_id").nullable()
    val dealId = integer("deal_id").nullable()
    val userId = integer("user_id")
    val status = varchar("status", 50).default("sent")
    val sentAt = datetime("sent_at")
}

object ApiKeys : IntIdTable("api_keys") {
    val key = varchar("key", 255).uniqueIndex()
    val secret = varchar("secret", 255)
    val name = varchar("name", 255)
    val userId = integer("user_id")
    val active = bool("active").default(true)
    val lastUsedAt = datetime("last_used_at").nullable()
    val createdAt = datetime("created_at")
}

object Webhooks : IntIdTable("webhooks") {
    val url = varchar("url", 1024)
    val events = varchar("events", 500)
    val secret = varchar("secret", 255).nullable()
    val active = bool("active").default(true)
    val createdBy = integer("created_by")
    val createdAt = datetime("created_at")
}

object Forecasts : IntIdTable("forecasts") {
    val period = varchar("period", 20)
    val ownerId = integer("owner_id")
    val predictedRevenue = decimal("predicted_revenue", 14, 2)
    val actualRevenue = decimal("actual_revenue", 14, 2).nullable()
    val confidence = decimal("confidence", 5, 2)
    val modelData = text("model_data").default("{}")
    val createdAt = datetime("created_at")
}

object AuditLog : IntIdTable("audit_log") {
    val userId = integer("user_id")
    val action = varchar("action", 100)
    val details = text("details").default("")
    val ipAddress = varchar("ip_address", 45)
    val userAgent = varchar("user_agent", 500).nullable()
    val createdAt = datetime("created_at")
}

// --- DTOs ---

@Serializable
data class LeadDTO(
    val id: Int? = null,
    val company: String,
    val contactName: String,
    val email: String,
    val phone: String? = null,
    val source: String = "manual",
    val status: String = "new",
    val score: Int = 0,
    val notes: String = "",
    val assignedTo: Int? = null,
    val customFields: String = "{}"
)

@Serializable
data class ContactDTO(
    val id: Int? = null,
    val firstName: String,
    val lastName: String,
    val email: String,
    val phone: String? = null,
    val company: String? = null,
    val title: String? = null,
    val address: String? = null,
    val notes: String = "",
    val leadId: Int? = null
)

@Serializable
data class DealDTO(
    val id: Int? = null,
    val name: String,
    val value: Double,
    val currency: String = "USD",
    val stage: String = "prospecting",
    val probability: Int = 10,
    val expectedCloseDate: String? = null,
    val contactId: Int,
    val notes: String = "",
    val metadata: String = "{}"
)

@Serializable
data class EmailSendRequest(
    val templateId: Int? = null,
    val to: String,
    val subject: String? = null,
    val body: String? = null,
    val variables: Map<String, String> = emptyMap(),
    val contactId: Int? = null,
    val dealId: Int? = null,
    val cc: String? = null,
    val bcc: String? = null,
    val replyTo: String? = null
)

@Serializable
data class WebhookDTO(
    val url: String,
    val events: String,
    val secret: String? = null
)

@Serializable
data class ImportRequest(
    val format: String,
    val targetEntity: String,
    val mappings: Map<String, String> = emptyMap(),
    val data: String? = null,
    val fileUrl: String? = null
)

@Serializable
data class ForecastRequest(
    val period: String,
    val modelType: String = "linear",
    val includeDeals: Boolean = true,
    val customFormula: String? = null
)

@Serializable
data class BulkActionRequest(
    val action: String,
    val ids: List<Int>,
    val params: Map<String, String> = emptyMap()
)
