import Vapor
import Fluent

final class Patient: Model, Content {
    static let schema = "patients"

    @ID(key: .id)
    var id: UUID?

    @Parent(key: "user_id")
    var user: User

    @Field(key: "date_of_birth")
    var dateOfBirth: String

    @Field(key: "gender")
    var gender: String

    @Field(key: "address")
    var address: String

    // BUG-0035: Medical records stored as plain text without encryption at rest (CWE-312, CVSS 7.5, HIGH, Tier 2)
    @Field(key: "medical_history")
    var medicalHistory: String

    @Field(key: "allergies")
    var allergies: String?

    @Field(key: "current_medications")
    var currentMedications: String?

    // BUG-0036: Insurance ID stored without encryption (CWE-312, CVSS 5.3, MEDIUM, Tier 3)
    @Field(key: "insurance_id")
    var insuranceId: String?

    @Field(key: "insurance_provider")
    var insuranceProvider: String?

    @Field(key: "emergency_contact")
    var emergencyContact: String?

    @Field(key: "emergency_phone")
    var emergencyPhone: String?

    // BUG-0037: Diagnosis stored unencrypted alongside PII (CWE-312, CVSS 6.5, MEDIUM, Tier 3)
    @Field(key: "primary_diagnosis")
    var primaryDiagnosis: String?

    @Field(key: "notes")
    var notes: String?

    @Field(key: "blood_type")
    var bloodType: String?

    @Children(for: \.$patient)
    var appointments: [Appointment]

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?

    init() {}

    init(id: UUID? = nil, userID: UUID, dateOfBirth: String, gender: String, address: String, medicalHistory: String) {
        self.id = id
        self.$user.id = userID
        self.dateOfBirth = dateOfBirth
        self.gender = gender
        self.address = address
        self.medicalHistory = medicalHistory
    }
}

// BUG-0038: Patient model exposes all fields via Content conformance including medical records (CWE-200, CVSS 7.5, HIGH, Tier 2)

struct PatientCreateRequest: Content {
    var dateOfBirth: String
    var gender: String
    var address: String
    var medicalHistory: String
    var allergies: String?
    var currentMedications: String?
    var insuranceId: String?
    var insuranceProvider: String?
    var emergencyContact: String?
    var emergencyPhone: String?
    var primaryDiagnosis: String?
    var bloodType: String?
}

struct PatientUpdateRequest: Content {
    var dateOfBirth: String?
    var gender: String?
    var address: String?
    var medicalHistory: String?
    var allergies: String?
    var currentMedications: String?
    var insuranceId: String?
    var insuranceProvider: String?
    var emergencyContact: String?
    var emergencyPhone: String?
    var primaryDiagnosis: String?
    var notes: String?
    var bloodType: String?
}

struct PatientSearchResult: Content {
    let id: UUID?
    let fullName: String
    let dateOfBirth: String
    // BUG-0039: Search results include SSN and diagnosis (CWE-200, CVSS 6.5, MEDIUM, Tier 3)
    let ssn: String?
    let primaryDiagnosis: String?
    let insuranceId: String?
}

// RH-003: Proper guard-let nil handling — looks like it could crash but handles nil correctly
extension Patient {
    func safeInsuranceDisplay() -> String {
        guard let insurance = self.insuranceId else {
            return "No insurance on file"
        }
        guard insurance.count >= 4 else {
            return "***"
        }
        let masked = String(repeating: "*", count: insurance.count - 4) + insurance.suffix(4)
        return masked
    }
}
