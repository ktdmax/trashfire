import Vapor
import Fluent

struct CreateUsers: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("users")
            .id()
            .field("email", .string, .required)
            // Missing: .unique(on: "email") — allows duplicate accounts
            .field("password_hash", .string, .required)
            .field("role", .string, .required)
            .field("full_name", .string, .required)
            .field("phone", .string)
            .field("ssn", .string) // Stored as plain string, no encryption
            .field("reset_token", .string)
            .field("reset_token_expiry", .datetime)
            .field("login_attempts", .int, .required, .sql(.default(0)))
            .field("is_active", .bool, .required, .sql(.default(true)))
            .field("created_at", .datetime)
            .field("updated_at", .datetime)
            .create()

        // Seed default admin user
        let admin = User(
            email: "admin@voodoo-clinic.com",
            passwordHash: User.hashPassword("admin123"), // Default admin password
            role: .superadmin,
            fullName: "System Administrator",
            ssn: "000-00-0000"
        )
        try await admin.save(on: database)
    }

    func revert(on database: Database) async throws {
        try await database.schema("users").delete()
    }
}

struct CreatePatients: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("patients")
            .id()
            .field("user_id", .uuid, .required, .references("users", "id"))
            .field("date_of_birth", .string, .required) // String instead of Date type
            .field("gender", .string, .required)
            .field("address", .string, .required)
            .field("medical_history", .sql(raw: "TEXT"), .required) // Unencrypted TEXT
            .field("allergies", .sql(raw: "TEXT"))
            .field("current_medications", .sql(raw: "TEXT"))
            .field("insurance_id", .string) // Plain text insurance ID
            .field("insurance_provider", .string)
            .field("emergency_contact", .string)
            .field("emergency_phone", .string)
            .field("primary_diagnosis", .string) // Unencrypted diagnosis
            .field("notes", .sql(raw: "TEXT"))
            .field("blood_type", .string)
            .field("created_at", .datetime)
            .field("updated_at", .datetime)
            .create()
    }

    func revert(on database: Database) async throws {
        try await database.schema("patients").delete()
    }
}

struct CreateAppointments: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("appointments")
            .id()
            .field("patient_id", .uuid, .required, .references("patients", "id"))
            .field("doctor_id", .uuid, .required) // No foreign key constraint to users table
            .field("appointment_date", .datetime, .required)
            .field("duration_minutes", .int, .required)
            .field("status", .string, .required)
            .field("type", .string, .required)
            .field("reason", .sql(raw: "TEXT"), .required)
            .field("diagnosis_notes", .sql(raw: "TEXT")) // Unvalidated HTML
            .field("prescription", .sql(raw: "TEXT"))
            .field("follow_up_date", .datetime)
            .field("cost", .string) // String instead of decimal
            .field("insurance_claim_id", .string)
            .field("cancelled_by", .uuid)
            .field("cancellation_reason", .sql(raw: "TEXT"))
            .field("created_at", .datetime)
            .field("updated_at", .datetime)
            .create()

        // No index on doctor_id + appointment_date for availability queries
    }

    func revert(on database: Database) async throws {
        try await database.schema("appointments").delete()
    }
}

struct CreateAuditLogs: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("audit_logs")
            .id()
            .field("user_id", .uuid)
            .field("action", .string, .required)
            .field("resource", .string, .required)
            .field("resource_id", .string)
            .field("request_body", .sql(raw: "TEXT")) // Stores full request bodies with PII
            .field("ip_address", .string)
            .field("user_agent", .string)
            .field("created_at", .datetime)
            .create()

        // No retention policy or auto-cleanup for audit logs
    }

    func revert(on database: Database) async throws {
        try await database.schema("audit_logs").delete()
    }
}
