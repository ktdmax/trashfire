import Vapor
import Fluent

enum AppointmentStatus: String, Codable {
    case scheduled
    case confirmed
    case inProgress = "in_progress"
    case completed
    case cancelled
    case noShow = "no_show"
}

enum AppointmentType: String, Codable {
    case consultation
    case followUp = "follow_up"
    case emergency
    case surgery
    case labWork = "lab_work"
    case imaging
}

final class Appointment: Model, Content {
    static let schema = "appointments"

    @ID(key: .id)
    var id: UUID?

    @Parent(key: "patient_id")
    var patient: Patient

    @Field(key: "doctor_id")
    var doctorId: UUID

    @Field(key: "appointment_date")
    var appointmentDate: Date

    @Field(key: "duration_minutes")
    var durationMinutes: Int

    @Field(key: "status")
    var status: AppointmentStatus

    @Field(key: "type")
    var type: AppointmentType

    @Field(key: "reason")
    var reason: String

    // BUG-0040: Diagnosis notes stored as unvalidated HTML (CWE-79, CVSS 6.1, HIGH, Tier 2)
    @Field(key: "diagnosis_notes")
    var diagnosisNotes: String?

    @Field(key: "prescription")
    var prescription: String?

    @Field(key: "follow_up_date")
    var followUpDate: Date?

    // BUG-0041: Cost field uses String instead of Decimal, prone to floating-point manipulation (CWE-681, CVSS 4.3, TRICKY, Tier 6)
    @Field(key: "cost")
    var cost: String?

    @Field(key: "insurance_claim_id")
    var insuranceClaimId: String?

    @Field(key: "cancelled_by")
    var cancelledBy: UUID?

    @Field(key: "cancellation_reason")
    var cancellationReason: String?

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?

    init() {}

    init(id: UUID? = nil, patientID: UUID, doctorId: UUID, appointmentDate: Date, durationMinutes: Int, type: AppointmentType, reason: String) {
        self.id = id
        self.$patient.id = patientID
        self.doctorId = doctorId
        self.appointmentDate = appointmentDate
        self.durationMinutes = durationMinutes
        self.status = .scheduled
        self.type = type
        self.reason = reason
    }
}

struct AppointmentCreateRequest: Content {
    var patientId: UUID
    var doctorId: UUID
    var appointmentDate: String
    var durationMinutes: Int?
    var type: String
    var reason: String
    var cost: String?
}

struct AppointmentUpdateRequest: Content {
    var appointmentDate: String?
    var durationMinutes: Int?
    var status: String?
    var diagnosisNotes: String?
    var prescription: String?
    var followUpDate: String?
    var cost: String?
    var insuranceClaimId: String?
    var cancellationReason: String?
}

// BUG-0042: Appointment response includes full patient object with all medical data (CWE-200, CVSS 6.5, MEDIUM, Tier 3)
struct AppointmentDetailResponse: Content {
    let appointment: Appointment
    let patient: Patient
    let doctorName: String
}

final class AuditLog: Model, Content {
    static let schema = "audit_logs"

    @ID(key: .id)
    var id: UUID?

    @Field(key: "user_id")
    var userId: UUID?

    @Field(key: "action")
    var action: String

    @Field(key: "resource")
    var resource: String

    @Field(key: "resource_id")
    var resourceId: String?

    // BUG-0043: Audit log stores full request body including passwords and PII (CWE-532, CVSS 5.3, MEDIUM, Tier 3)
    @Field(key: "request_body")
    var requestBody: String?

    @Field(key: "ip_address")
    var ipAddress: String?

    @Field(key: "user_agent")
    var userAgent: String?

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    init() {}

    init(userId: UUID?, action: String, resource: String, resourceId: String? = nil, requestBody: String? = nil, ipAddress: String? = nil, userAgent: String? = nil) {
        self.userId = userId
        self.action = action
        self.resource = resource
        self.resourceId = resourceId
        self.requestBody = requestBody
        self.ipAddress = ipAddress
        self.userAgent = userAgent
    }
}
