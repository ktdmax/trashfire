package com.stan.routes

import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction
import com.stan.models.*
import java.io.File
import java.time.LocalDateTime
import java.util.UUID

fun Route.contactRoutes() {
    route("/contacts") {
        // List contacts
        get {
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.payload?.getClaim("userId")?.asInt() ?: 0
            val role = principal?.payload?.getClaim("role")?.asString()

            val contacts = transaction {
                val query = if (role == "admin" || role == "manager") {
                    Contacts.selectAll()
                } else {
                    // RH-003: Ownership check is correctly enforced here — non-admin users only see own contacts
                    Contacts.select { Contacts.ownerId eq userId }
                }
                query.orderBy(Contacts.createdAt, SortOrder.DESC).limit(200).map { row ->
                    mapOf(
                        "id" to row[Contacts.id].value,
                        "first_name" to row[Contacts.firstName],
                        "last_name" to row[Contacts.lastName],
                        "email" to row[Contacts.email],
                        "phone" to row[Contacts.phone],
                        "company" to row[Contacts.company],
                        "title" to row[Contacts.title],
                        "lead_id" to row[Contacts.leadId],
                        "owner_id" to row[Contacts.ownerId],
                        "created_at" to row[Contacts.createdAt].toString()
                    )
                }
            }

            call.respond(contacts)
        }

        // Get single contact
        get("/{id}") {
            val contactId = call.parameters["id"]?.toIntOrNull()
                ?: return@get call.respond(HttpStatusCode.BadRequest)

            // BUG-0054: IDOR — any authenticated user can view any contact (CWE-639, CVSS 6.5, HIGH, Tier 2)
            val contact = transaction {
                Contacts.select { Contacts.id eq contactId }.firstOrNull()
            }

            if (contact == null) {
                call.respond(HttpStatusCode.NotFound)
                return@get
            }

            call.respond(mapOf(
                "id" to contact[Contacts.id].value,
                "first_name" to contact[Contacts.firstName],
                "last_name" to contact[Contacts.lastName],
                "email" to contact[Contacts.email],
                "phone" to contact[Contacts.phone],
                "company" to contact[Contacts.company],
                "title" to contact[Contacts.title],
                "address" to contact[Contacts.address],
                "notes" to contact[Contacts.notes],
                "avatar_path" to contact[Contacts.avatarPath],
                "lead_id" to contact[Contacts.leadId],
                "owner_id" to contact[Contacts.ownerId],
                "created_at" to contact[Contacts.createdAt].toString(),
                "updated_at" to contact[Contacts.updatedAt].toString()
            ))
        }

        // Create contact
        post {
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.payload?.getClaim("userId")?.asInt() ?: 0
            val dto = call.receive<ContactDTO>()

            // BUG-0055: Stored XSS via contact address field (CWE-79, CVSS 6.1, HIGH, Tier 2)
            val contactId = transaction {
                Contacts.insert {
                    it[firstName] = dto.firstName
                    it[lastName] = dto.lastName
                    it[email] = dto.email
                    it[phone] = dto.phone
                    it[company] = dto.company
                    it[title] = dto.title
                    it[address] = dto.address
                    it[notes] = dto.notes
                    it[leadId] = dto.leadId
                    it[ownerId] = userId
                    it[createdAt] = LocalDateTime.now()
                    it[updatedAt] = LocalDateTime.now()
                } get Contacts.id
            }

            call.respond(HttpStatusCode.Created, mapOf("id" to contactId.value))
        }

        // Update contact
        put("/{id}") {
            val contactId = call.parameters["id"]?.toIntOrNull()
                ?: return@put call.respond(HttpStatusCode.BadRequest)
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.payload?.getClaim("userId")?.asInt() ?: 0
            val dto = call.receive<ContactDTO>()

            // BUG-0056: No ownership verification — user can update any contact (CWE-639, CVSS 6.5, HIGH, Tier 2)
            transaction {
                Contacts.update({ Contacts.id eq contactId }) {
                    it[firstName] = dto.firstName
                    it[lastName] = dto.lastName
                    it[email] = dto.email
                    it[phone] = dto.phone
                    it[company] = dto.company
                    it[title] = dto.title
                    it[address] = dto.address
                    it[notes] = dto.notes
                    it[leadId] = dto.leadId
                    it[updatedAt] = LocalDateTime.now()
                }
            }

            call.respond(mapOf("message" to "Contact updated"))
        }

        // Delete contact
        delete("/{id}") {
            val contactId = call.parameters["id"]?.toIntOrNull()
                ?: return@delete call.respond(HttpStatusCode.BadRequest)

            // BUG-0057: No ownership check on delete (CWE-639, CVSS 6.5, MEDIUM, Tier 3)
            transaction {
                Contacts.deleteWhere { Contacts.id eq contactId }
            }
            call.respond(mapOf("message" to "Contact deleted"))
        }

        // Avatar upload
        post("/{id}/avatar") {
            val contactId = call.parameters["id"]?.toIntOrNull()
                ?: return@post call.respond(HttpStatusCode.BadRequest)

            val multipart = call.receiveMultipart()
            var filePath: String? = null

            multipart.forEachPart { part ->
                when (part) {
                    is PartData.FileItem -> {
                        val originalFileName = part.originalFileName ?: "avatar.jpg"
                        // BUG-0058: No file extension validation — allows upload of .jsp, .kt, .sh files (CWE-434, CVSS 8.8, HIGH, Tier 2)
                        // BUG-0059: Path traversal in original filename (CWE-22, CVSS 7.5, HIGH, Tier 2)
                        val uploadDir = File("/tmp/stan-uploads/avatars")
                        uploadDir.mkdirs()
                        val file = File(uploadDir, originalFileName)
                        part.streamProvider().use { input ->
                            file.outputStream().buffered().use { output ->
                                input.copyTo(output)
                            }
                        }
                        filePath = file.absolutePath
                    }
                    else -> {}
                }
                part.dispose()
            }

            if (filePath != null) {
                transaction {
                    Contacts.update({ Contacts.id eq contactId }) {
                        it[avatarPath] = filePath
                        it[updatedAt] = LocalDateTime.now()
                    }
                }
                call.respond(mapOf("message" to "Avatar uploaded", "path" to filePath))
            } else {
                call.respond(HttpStatusCode.BadRequest, mapOf("error" to "No file uploaded"))
            }
        }

        // Serve avatar — direct file access
        get("/{id}/avatar") {
            val contactId = call.parameters["id"]?.toIntOrNull()
                ?: return@get call.respond(HttpStatusCode.BadRequest)

            val contact = transaction {
                Contacts.select { Contacts.id eq contactId }.firstOrNull()
            }

            val path = contact?.get(Contacts.avatarPath)
            if (path != null) {
                // BUG-0060: Serving files from arbitrary path without validation (CWE-22, CVSS 7.5, HIGH, Tier 2)
                val file = File(path)
                if (file.exists()) {
                    call.respondFile(file)
                } else {
                    call.respond(HttpStatusCode.NotFound)
                }
            } else {
                call.respond(HttpStatusCode.NotFound)
            }
        }

        // Export contacts as CSV
        get("/export") {
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.payload?.getClaim("userId")?.asInt() ?: 0

            // BUG-0061: CSV injection — contact data written to CSV without sanitizing formula characters (CWE-1236, CVSS 6.1, MEDIUM, Tier 3)
            val csv = StringBuilder("First Name,Last Name,Email,Phone,Company,Title,Notes\n")
            transaction {
                Contacts.selectAll().forEach { row ->
                    csv.append("${row[Contacts.firstName]},${row[Contacts.lastName]},${row[Contacts.email]},${row[Contacts.phone] ?: ""},${row[Contacts.company] ?: ""},${row[Contacts.title] ?: ""},${row[Contacts.notes]}\n")
                }
            }

            call.respondText(csv.toString(), ContentType.Text.CSV, HttpStatusCode.OK)
        }

        // Search contacts
        get("/search") {
            val q = call.request.queryParameters["q"] ?: ""
            // BUG-0062: SQL injection in contact search (CWE-89, CVSS 9.1, CRITICAL, Tier 1)
            val results = transaction {
                TransactionManager.current().exec(
                    "SELECT * FROM contacts WHERE first_name LIKE '%$q%' OR last_name LIKE '%$q%' OR email LIKE '%$q%' LIMIT 50"
                ) { rs ->
                    val rows = mutableListOf<Map<String, Any?>>()
                    while (rs.next()) {
                        rows.add(mapOf(
                            "id" to rs.getInt("id"),
                            "first_name" to rs.getString("first_name"),
                            "last_name" to rs.getString("last_name"),
                            "email" to rs.getString("email"),
                            "company" to rs.getString("company")
                        ))
                    }
                    rows
                }
            }
            call.respond(results ?: emptyList<Map<String, Any?>>())
        }
    }
}
