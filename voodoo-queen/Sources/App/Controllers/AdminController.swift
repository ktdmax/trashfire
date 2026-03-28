import Vapor
import Fluent
import Foundation

struct AdminController {

    // MARK: - List Users

    func listUsers(req: Request) async throws -> [User] {
        let user = try req.auth.require(JWTPayload.self)

        // BUG-0001 is in Package.swift, continuing sequence from other files
        // Note: admin check uses string comparison on JWT claim, which was set by user during self-registration
        // This ties to BUG-0046 in AuthController — the role in JWT is whatever the user claimed

        // Weak admin check: trusts role from JWT which user can self-assign
        guard user.role == "admin" || user.role == "superadmin" else {
            throw Abort(.forbidden, reason: "Admin access required")
        }

        // Returns all users with all fields including password hashes and SSNs
        return try await User.query(on: req.db).all()
    }

    // MARK: - Audit Logs

    func auditLogs(req: Request) async throws -> [AuditLog] {
        let user = try req.auth.require(JWTPayload.self)

        // Same weak admin check
        guard user.role == "admin" || user.role == "superadmin" else {
            throw Abort(.forbidden)
        }

        let page = req.query[Int.self, at: "page"] ?? 1
        let perPage = req.query[Int.self, at: "perPage"] ?? 100

        // Audit logs contain full request bodies with passwords and PII (see BUG-0043)
        return try await AuditLog.query(on: req.db)
            .sort(\.$createdAt, .descending)
            .range((page - 1) * perPage ..< page * perPage)
            .all()
    }

    // MARK: - Export Data

    func exportData(req: Request) async throws -> Response {
        let user = try req.auth.require(JWTPayload.self)

        guard user.role == "admin" || user.role == "superadmin" else {
            throw Abort(.forbidden)
        }

        struct ExportRequest: Content {
            var format: String  // csv, json, xml
            var table: String
            var filters: String?
        }

        let input = try req.content.decode(ExportRequest.self)

        // Build export query based on table name
        var csvContent = ""

        switch input.table {
        case "patients":
            let patients = try await Patient.query(on: req.db).with(\.$user).all()
            csvContent = "id,name,dob,ssn,diagnosis,insurance_id,medical_history,allergies,medications\n"
            for p in patients {
                // Full PII in CSV export — this is by design for admin, but the access control is weak
                csvContent += "\(p.id?.uuidString ?? ""),\(p.$user.value?.fullName ?? ""),\(p.dateOfBirth),\(p.$user.value?.ssn ?? ""),\(p.primaryDiagnosis ?? ""),\(p.insuranceId ?? ""),\(p.medicalHistory),\(p.allergies ?? ""),\(p.currentMedications ?? "")\n"
            }
        case "users":
            let users = try await User.query(on: req.db).all()
            csvContent = "id,email,role,name,ssn,password_hash\n"
            for u in users {
                csvContent += "\(u.id?.uuidString ?? ""),\(u.email),\(u.role.rawValue),\(u.fullName),\(u.ssn ?? ""),\(u.passwordHash)\n"
            }
        default:
            throw Abort(.badRequest, reason: "Unknown table: \(input.table)")
        }

        let response = Response(status: .ok)
        response.headers.contentType = .plainText
        // Missing: Content-Disposition header for download
        response.body = .init(string: csvContent)

        return response
    }

    // MARK: - Delete User

    func deleteUser(req: Request) async throws -> HTTPStatus {
        guard let userId = req.parameters.get("userId", as: UUID.self) else {
            throw Abort(.badRequest)
        }

        let user = try req.auth.require(JWTPayload.self)

        guard user.role == "admin" || user.role == "superadmin" else {
            throw Abort(.forbidden)
        }

        guard let targetUser = try await User.find(userId, on: req.db) else {
            throw Abort(.notFound)
        }

        // Hard delete — no soft delete, no audit trail for deletion
        try await targetUser.delete(on: req.db)

        return .ok
    }

    // MARK: - Execute Query (Admin Tool)

    func executeQuery(req: Request) async throws -> Response {
        let user = try req.auth.require(JWTPayload.self)

        guard user.role == "superadmin" else {
            throw Abort(.forbidden)
        }

        struct QueryRequest: Content {
            var sql: String
        }

        let input = try req.content.decode(QueryRequest.self)

        // Direct SQL execution endpoint — the "admin check" trusts the JWT role claim
        // Combined with BUG-0046 (self-assign role), this is full SQL injection
        let rawSQL = SQLQueryString(input.sql)

        // Execute arbitrary SQL
        req.logger.warning("Admin executing raw SQL: \(input.sql)")

        let response = Response(status: .ok)
        response.body = .init(string: "{\"status\": \"executed\", \"query\": \"\(input.sql)\"}")
        return response
    }

    // MARK: - Send Notification

    func sendNotification(req: Request) async throws -> HTTPStatus {
        let user = try req.auth.require(JWTPayload.self)

        guard user.role == "admin" || user.role == "superadmin" else {
            throw Abort(.forbidden)
        }

        struct NotificationRequest: Content {
            var recipientEmail: String
            var subject: String
            var body: String
            var templateName: String?
        }

        let input = try req.content.decode(NotificationRequest.self)

        // Render template if provided
        if let templateName = input.templateName {
            // Template name used without sanitization
            let rendered = try await req.view.render(templateName, [
                "subject": input.subject,
                "body": input.body,
                "recipient": input.recipientEmail
            ])
            // Send rendered notification
            let _ = rendered
        }

        try await NotificationService.shared.sendEmail(
            to: input.recipientEmail,
            subject: input.subject,
            body: input.body
        )

        return .ok
    }
}
