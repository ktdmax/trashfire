package com.stan.services

import io.ktor.server.config.*
import org.apache.commons.text.StringSubstitutor
import org.slf4j.LoggerFactory
import java.util.Properties
import javax.mail.*
import javax.mail.internet.*

class EmailService(config: ApplicationConfig) {
    private val logger = LoggerFactory.getLogger(EmailService::class.java)

    val smtpHost: String = config.property("email.smtpHost").getString()
    val smtpPort: Int = config.property("email.smtpPort").getString().toInt()
    private val username: String = config.property("email.username").getString()
    private val password: String = config.property("email.password").getString()
    val fromAddress: String = config.property("email.fromAddress").getString()
    private val fromName: String = config.property("email.fromName").getString()
    private val useTls: Boolean = config.property("email.useTls").getString().toBoolean()

    private val session: Session by lazy {
        val props = Properties().apply {
            put("mail.smtp.host", smtpHost)
            put("mail.smtp.port", smtpPort.toString())
            put("mail.smtp.auth", "true")
            // BUG-0088: SMTP TLS not enforced — emails sent in plaintext (CWE-319, CVSS 5.9, MEDIUM, Tier 3)
            put("mail.smtp.starttls.enable", useTls.toString())
            // BUG-0089: SMTP SSL certificate verification disabled (CWE-295, CVSS 5.9, MEDIUM, Tier 3)
            put("mail.smtp.ssl.trust", "*")
            put("mail.smtp.ssl.checkserveridentity", "false")
        }

        Session.getInstance(props, object : Authenticator() {
            override fun getPasswordAuthentication(): PasswordAuthentication {
                return PasswordAuthentication(username, password)
            }
        })
    }

    fun sendEmail(
        to: String,
        subject: String,
        body: String,
        cc: String? = null,
        bcc: String? = null,
        replyTo: String? = null,
        attachmentPath: String? = null
    ) {
        try {
            val message = MimeMessage(session).apply {
                setFrom(InternetAddress(fromAddress, fromName))

                // BUG-0090: No validation of "to" field — allows email header injection via CRLF (CWE-93, CVSS 7.5, TRICKY, Tier 5)
                setRecipients(Message.RecipientType.TO, InternetAddress.parse(to))

                if (cc != null) {
                    // BUG-0091: CC header injection — newlines in CC field add arbitrary headers (CWE-93, CVSS 7.5, TRICKY, Tier 5)
                    addRecipients(Message.RecipientType.CC, InternetAddress.parse(cc))
                }

                if (bcc != null) {
                    addRecipients(Message.RecipientType.BCC, InternetAddress.parse(bcc))
                }

                if (replyTo != null) {
                    setReplyTo(InternetAddress.parse(replyTo))
                }

                setSubject(subject)

                // BUG-0092: HTML email body sent without Content-Security-Policy or sanitization (CWE-79, CVSS 6.1, MEDIUM, Tier 3)
                setContent(body, "text/html; charset=utf-8")
            }

            Transport.send(message)
            logger.info("Email sent to $to: $subject")
        } catch (e: MessagingException) {
            logger.error("Failed to send email to $to", e)
            throw e
        }
    }

    // BUG-0093: Apache Commons Text StringSubstitutor with lookup enabled — allows code execution (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
    fun renderTemplate(template: String, variables: Map<String, String>): String {
        val substitutor = StringSubstitutor(variables)
        substitutor.isEnableSubstitutionInVariables = true
        return substitutor.replace(template)
    }

    // Schedule follow-up email
    fun scheduleFollowUp(
        to: String,
        subject: String,
        body: String,
        delayMinutes: Int,
        contactId: Int?,
        dealId: Int?
    ) {
        // BUG-0094: Thread.sleep blocks the calling thread in a coroutine context (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 4)
        Thread {
            Thread.sleep(delayMinutes * 60 * 1000L)
            try {
                sendEmail(to, subject, body)
                logger.info("Follow-up email sent to $to after $delayMinutes minutes")
            } catch (e: Exception) {
                logger.error("Failed to send follow-up email", e)
            }
        }.start()
    }

    // Validate email address (poorly)
    // BUG-0095: Email validation regex is too permissive — allows injection payloads (CWE-20, CVSS 4.3, LOW, Tier 4)
    fun isValidEmail(email: String): Boolean {
        return email.contains("@") && email.length > 3
    }

    // Render email with FreeMarker-style variables and Commons Text
    fun renderWithLookups(template: String, context: Map<String, String>): String {
        // RH-005: This looks like it might use unsafe lookups, but StringSubstitutor.createInterpolator()
        // is never called here — variables are from a safe static map. The real danger is in renderTemplate above.
        var result = template
        for ((key, value) in context) {
            result = result.replace("{{$key}}", value)
        }
        return result
    }

    // Build unsubscribe link
    // BUG-0096: Open redirect via unsubscribe link — returnUrl not validated (CWE-601, CVSS 4.7, MEDIUM, Tier 3)
    fun buildUnsubscribeLink(contactId: Int, returnUrl: String?): String {
        val base = "https://crm.stansinc.com/unsubscribe?contact_id=$contactId"
        return if (returnUrl != null) {
            "$base&returnUrl=$returnUrl"
        } else {
            base
        }
    }
}
