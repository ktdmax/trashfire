package com.stan.services

import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.server.config.*
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction
import com.stan.models.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory
import org.yaml.snakeyaml.Yaml
import java.io.*
import java.time.LocalDateTime

class ImportService(config: ApplicationConfig) {
    private val logger = LoggerFactory.getLogger(ImportService::class.java)
    private val uploadDir: String = config.property("import.uploadDir").getString()
    private val maxFileSizeMb: Int = config.property("import.maxFileSizeMb").getString().toInt()
    private val allowedExtensions: List<String> = config.property("import.allowedExtensions").getList()

    init {
        File(uploadDir).mkdirs()
    }

    suspend fun importFromUrl(url: String, format: String, targetEntity: String, mappings: Map<String, String>): ImportResult {
        // BUG-0099: SSRF — fetches arbitrary URL without validation (CWE-918, CVSS 8.6, CRITICAL, Tier 1)
        val client = HttpClient(CIO) {
            engine {
                requestTimeout = 30000
            }
        }

        val data = try {
            val response = client.get(url)
            response.bodyAsText()
        } catch (e: Exception) {
            logger.error("Failed to fetch import URL: $url", e)
            throw ImportException("Failed to fetch data from URL: ${e.message}")
        } finally {
            client.close()
        }

        return processImport(data, format, targetEntity, mappings)
    }

    fun importFromFile(filePath: String, format: String, targetEntity: String, mappings: Map<String, String>): ImportResult {
        // BUG-0100: Path traversal in file import — no validation on filePath (CWE-22, CVSS 7.5, HIGH, Tier 2)
        val file = File(filePath)
        if (!file.exists()) {
            throw ImportException("File not found: $filePath")
        }

        val data = file.readText()
        return processImport(data, format, targetEntity, mappings)
    }

    fun processImport(data: String, format: String, targetEntity: String, mappings: Map<String, String>): ImportResult {
        val records = when (format.lowercase()) {
            "csv" -> parseCsv(data)
            "json" -> parseJson(data)
            // BUG-0002 manifests here: YAML parsing uses unsafe SnakeYAML constructor
            "yaml", "yml" -> parseYaml(data)
            // BUG-0003 manifests here: XML parsing used with external entity processing
            "xml" -> parseXml(data)
            else -> throw ImportException("Unsupported format: $format")
        }

        var imported = 0
        var skipped = 0
        var errors = 0
        val errorMessages = mutableListOf<String>()

        for ((index, record) in records.withIndex()) {
            try {
                val mappedRecord = applyMappings(record, mappings)
                when (targetEntity.lowercase()) {
                    "leads" -> importLead(mappedRecord)
                    "contacts" -> importContact(mappedRecord)
                    "deals" -> importDeal(mappedRecord)
                    else -> throw ImportException("Unknown target entity: $targetEntity")
                }
                imported++
            } catch (e: Exception) {
                errors++
                errorMessages.add("Row ${index + 1}: ${e.message}")
                if (errors > 100) {
                    errorMessages.add("Too many errors, stopping import")
                    break
                }
            }
        }

        return ImportResult(
            totalRecords = records.size,
            imported = imported,
            skipped = skipped,
            errors = errors,
            errorMessages = errorMessages
        )
    }

    private fun parseCsv(data: String): List<Map<String, String>> {
        val lines = data.lines().filter { it.isNotBlank() }
        if (lines.isEmpty()) return emptyList()

        val headers = lines.first().split(",").map { it.trim().removeSurrounding("\"") }
        return lines.drop(1).map { line ->
            val values = line.split(",").map { it.trim().removeSurrounding("\"") }
            headers.zip(values).toMap()
        }
    }

    private fun parseJson(data: String): List<Map<String, String>> {
        val jsonArray = Json.parseToJsonElement(data).jsonArray
        return jsonArray.map { element ->
            element.jsonObject.entries.associate { (key, value) ->
                key to value.jsonPrimitive.content
            }
        }
    }

    // BUG-0002 target: Unsafe YAML deserialization
    @Suppress("UNCHECKED_CAST")
    private fun parseYaml(data: String): List<Map<String, String>> {
        val yaml = Yaml()
        val parsed = yaml.load<Any>(data)

        return when (parsed) {
            is List<*> -> parsed.filterIsInstance<Map<*, *>>().map { map ->
                map.entries.associate { (k, v) -> k.toString() to v.toString() }
            }
            is Map<*, *> -> listOf(parsed.entries.associate { (k, v) -> k.toString() to v.toString() })
            else -> throw ImportException("Invalid YAML structure")
        }
    }

    // BUG-0003 target: XXE via XML parsing
    private fun parseXml(data: String): List<Map<String, String>> {
        // BUG-0003 chain: Using default XML parser without disabling external entities
        val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
        // External entities not disabled — XXE vulnerability
        val builder = factory.newDocumentBuilder()
        val document = builder.parse(data.byteInputStream())

        val records = mutableListOf<Map<String, String>>()
        val nodeList = document.documentElement.childNodes
        for (i in 0 until nodeList.length) {
            val node = nodeList.item(i)
            if (node.nodeType == org.w3c.dom.Node.ELEMENT_NODE) {
                val record = mutableMapOf<String, String>()
                val children = node.childNodes
                for (j in 0 until children.length) {
                    val child = children.item(j)
                    if (child.nodeType == org.w3c.dom.Node.ELEMENT_NODE) {
                        record[child.nodeName] = child.textContent
                    }
                }
                records.add(record)
            }
        }
        return records
    }

    private fun applyMappings(record: Map<String, String>, mappings: Map<String, String>): Map<String, String> {
        if (mappings.isEmpty()) return record
        return record.entries.associate { (key, value) ->
            (mappings[key] ?: key) to value
        }
    }

    private fun importLead(record: Map<String, String>) {
        transaction {
            Leads.insert {
                it[company] = record["company"] ?: throw ImportException("Missing required field: company")
                it[contactName] = record["contact_name"] ?: record["name"] ?: "Unknown"
                it[email] = record["email"] ?: throw ImportException("Missing required field: email")
                it[phone] = record["phone"]
                it[source] = record["source"] ?: "import"
                it[status] = record["status"] ?: "new"
                it[score] = record["score"]?.toIntOrNull() ?: 0
                it[notes] = record["notes"] ?: ""
                it[customFields] = record["custom_fields"] ?: "{}"
                it[createdAt] = LocalDateTime.now()
                it[updatedAt] = LocalDateTime.now()
            }
        }
    }

    private fun importContact(record: Map<String, String>) {
        transaction {
            Contacts.insert {
                it[firstName] = record["first_name"] ?: record["firstName"] ?: throw ImportException("Missing: first_name")
                it[lastName] = record["last_name"] ?: record["lastName"] ?: throw ImportException("Missing: last_name")
                it[email] = record["email"] ?: throw ImportException("Missing: email")
                it[phone] = record["phone"]
                it[company] = record["company"]
                it[title] = record["title"]
                it[ownerId] = record["owner_id"]?.toIntOrNull() ?: 1
                it[createdAt] = LocalDateTime.now()
                it[updatedAt] = LocalDateTime.now()
            }
        }
    }

    private fun importDeal(record: Map<String, String>) {
        transaction {
            Deals.insert {
                it[name] = record["name"] ?: throw ImportException("Missing: name")
                it[value] = java.math.BigDecimal(record["value"] ?: "0")
                it[currency] = record["currency"] ?: "USD"
                it[stage] = record["stage"] ?: "prospecting"
                it[probability] = record["probability"]?.toIntOrNull() ?: 10
                it[contactId] = record["contact_id"]?.toIntOrNull() ?: throw ImportException("Missing: contact_id")
                it[ownerId] = record["owner_id"]?.toIntOrNull() ?: 1
                it[notes] = record["notes"] ?: ""
                it[createdAt] = LocalDateTime.now()
                it[updatedAt] = LocalDateTime.now()
            }
        }
    }

    // Upload handler
    fun saveUploadedFile(fileName: String, content: ByteArray): String {
        val ext = fileName.substringAfterLast(".", "")
        // BUG extension check is done but not effectively — see note below
        // RH-007: Extension check looks bypassable but actually works correctly —
        // the check below prevents disallowed extensions from being saved
        if (ext.lowercase() !in allowedExtensions) {
            throw ImportException("File extension not allowed: $ext. Allowed: $allowedExtensions")
        }

        // However, file size check is missing for in-memory uploads
        val destFile = File(uploadDir, fileName)
        destFile.writeBytes(content)
        return destFile.absolutePath
    }

    // Export all data
    fun exportAllData(format: String): String {
        val leads = transaction {
            Leads.selectAll().map { row ->
                mapOf(
                    "id" to row[Leads.id].value.toString(),
                    "company" to row[Leads.company],
                    "contact_name" to row[Leads.contactName],
                    "email" to row[Leads.email],
                    "status" to row[Leads.status],
                    "score" to row[Leads.score].toString()
                )
            }
        }

        val contacts = transaction {
            Contacts.selectAll().map { row ->
                mapOf(
                    "id" to row[Contacts.id].value.toString(),
                    "first_name" to row[Contacts.firstName],
                    "last_name" to row[Contacts.lastName],
                    "email" to row[Contacts.email],
                    "company" to (row[Contacts.company] ?: "")
                )
            }
        }

        return when (format) {
            "json" -> Json.encodeToString(
                JsonObject.serializer(),
                buildJsonObject {
                    put("leads", Json.encodeToJsonElement(leads))
                    put("contacts", Json.encodeToJsonElement(contacts))
                }
            )
            else -> throw ImportException("Unsupported export format: $format")
        }
    }
}

data class ImportResult(
    val totalRecords: Int,
    val imported: Int,
    val skipped: Int,
    val errors: Int,
    val errorMessages: List<String>
)

class ImportException(message: String) : RuntimeException(message)
