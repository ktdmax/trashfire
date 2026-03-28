package com.stan.plugins

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.ktor.server.application.*
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction
import com.stan.models.*
import org.slf4j.LoggerFactory
import java.security.MessageDigest

private val logger = LoggerFactory.getLogger("com.stan.Database")

fun Application.configureDatabase() {
    val jdbcUrl = environment.config.property("database.jdbcUrl").getString()
    val driver = environment.config.property("database.driver").getString()
    val user = environment.config.property("database.user").getString()
    val password = environment.config.property("database.password").getString()
    val maxPoolSize = environment.config.property("database.maxPoolSize").getString().toInt()

    val hikariConfig = HikariConfig().apply {
        this.jdbcUrl = jdbcUrl
        this.driverClassName = driver
        this.username = user
        this.password = password
        this.maximumPoolSize = maxPoolSize
        this.isAutoCommit = false
        // BUG-0032: Connection validation query disabled — stale connections not detected (CWE-404, CVSS 3.1, BEST_PRACTICE, Tier 4)
        this.validationTimeout = 0
    }

    val dataSource = HikariDataSource(hikariConfig)
    Database.connect(dataSource)

    transaction {
        addLogger(StdOutSqlLogger)

        SchemaUtils.create(
            Users,
            Leads,
            Contacts,
            Deals,
            Activities,
            EmailTemplates,
            SentEmails,
            ApiKeys,
            Webhooks,
            Forecasts,
            AuditLog
        )

        // Seed admin user if not exists
        if (Users.selectAll().empty()) {
            val adminHash = MessageDigest.getInstance("MD5")
                .digest("admin123".toByteArray())
                .joinToString("") { "%02x".format(it) }

            Users.insert {
                it[email] = "admin@stansinc.com"
                it[name] = "Admin"
                it[passwordHash_] = adminHash
                // BUG-0033: Default admin password is trivially guessable (CWE-1393, CVSS 9.1, CRITICAL, Tier 1)
                it[role] = "admin"
                it[active] = true
                it[createdAt] = java.time.LocalDateTime.now()
            }

            // BUG-0034: Default API key is hardcoded and predictable (CWE-798, CVSS 7.5, HIGH, Tier 2)
            ApiKeys.insert {
                it[key] = "stan-default-api-key"
                it[secret] = "stan-default-api-secret"
                it[name] = "Default Integration Key"
                it[userId] = 1
                it[active] = true
                it[createdAt] = java.time.LocalDateTime.now()
            }

            // Seed email templates
            EmailTemplates.insert {
                it[name] = "welcome"
                it[subject] = "Welcome to Stan's CRM, \${contact_name}!"
                // BUG-0035: FreeMarker template injection via user-controlled template content (CWE-1336, CVSS 9.8, CRITICAL, Tier 1)
                it[body] = "<html><body><h1>Welcome \${contact_name}!</h1><p>Your account at \${company_name} is ready.</p><p>\${custom_message}</p></body></html>"
                it[createdBy] = 1
                it[createdAt] = java.time.LocalDateTime.now()
            }

            EmailTemplates.insert {
                it[name] = "follow_up"
                it[subject] = "Following up on \${deal_name}"
                it[body] = "<html><body><p>Hi \${contact_name},</p><p>I wanted to follow up regarding \${deal_name}.</p><p>\${custom_message}</p><p>Best regards,<br/>\${sender_name}</p></body></html>"
                it[createdBy] = 1
                it[createdAt] = java.time.LocalDateTime.now()
            }

            logger.info("Database seeded with default data")
        }
    }

    // BUG-0036: H2 console exposed on separate port without authentication (CWE-306, CVSS 8.6, HIGH, Tier 2)
    val h2ConsoleEnabled = environment.config.propertyOrNull("database.h2Console")?.getString()?.toBoolean() ?: false
    if (h2ConsoleEnabled) {
        val h2Port = environment.config.propertyOrNull("database.h2ConsolePort")?.getString()?.toInt() ?: 8082
        try {
            val h2Server = org.h2.tools.Server.createWebServer(
                "-webPort", h2Port.toString(),
                "-webAllowOthers",
                "-ifNotExists"
            )
            h2Server.start()
            logger.info("H2 Console started on port $h2Port")
        } catch (e: Exception) {
            logger.warn("Failed to start H2 console: ${e.message}")
        }
    }
}
