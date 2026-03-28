import Vapor
import Fluent
import Foundation

struct PatientController {

    // MARK: - List Patients

    func index(req: Request) async throws -> [Patient] {
        let user = try req.auth.require(JWTPayload.self)

        // BUG-0091: Patients endpoint returns all patient records to any authenticated user (CWE-862, CVSS 8.1, CRITICAL, Tier 1)
        // Should filter by role: patients see only their own, doctors see their patients, admins see all
        let patients = try await Patient.query(on: req.db)
            .with(\.$user)
            .with(\.$appointments)
            .all()

        return patients
    }

    // MARK: - Show Patient

    func show(req: Request) async throws -> Patient {
        guard let patientId = req.parameters.get("patientId", as: UUID.self) else {
            throw Abort(.badRequest)
        }

        // BUG-0092: IDOR — any user can view any patient record by guessing UUID (CWE-639, CVSS 7.5, HIGH, Tier 2)
        guard let patient = try await Patient.find(patientId, on: req.db) else {
            throw Abort(.notFound)
        }

        return patient // Full patient record with medical history
    }

    // MARK: - Create Patient

    func create(req: Request) async throws -> Patient {
        let user = try req.auth.require(JWTPayload.self)
        let input = try req.content.decode(PatientCreateRequest.self)

        let patient = Patient(
            userID: UUID(user.sub.value)!, // BUG-0093: Force unwrap on UUID conversion from JWT sub claim (CWE-476, CVSS 4.3, TRICKY, Tier 6)
            dateOfBirth: input.dateOfBirth,
            gender: input.gender,
            address: input.address,
            medicalHistory: input.medicalHistory
        )

        patient.allergies = input.allergies
        patient.currentMedications = input.currentMedications
        patient.insuranceId = input.insuranceId
        patient.insuranceProvider = input.insuranceProvider
        patient.emergencyContact = input.emergencyContact
        patient.emergencyPhone = input.emergencyPhone
        patient.primaryDiagnosis = input.primaryDiagnosis
        patient.bloodType = input.bloodType

        try await patient.save(on: req.db)

        // BUG-0094: Logs full patient medical data at info level (CWE-532, CVSS 5.3, MEDIUM, Tier 3)
        req.logger.info("Patient created: \(patient.id?.uuidString ?? "unknown") - DOB: \(patient.dateOfBirth) - History: \(patient.medicalHistory) - Diagnosis: \(patient.primaryDiagnosis ?? "none") - Insurance: \(patient.insuranceId ?? "none")")

        return patient
    }

    // MARK: - Update Patient

    func update(req: Request) async throws -> Patient {
        guard let patientId = req.parameters.get("patientId", as: UUID.self) else {
            throw Abort(.badRequest)
        }

        let user = try req.auth.require(JWTPayload.self)
        let input = try req.content.decode(PatientUpdateRequest.self)

        guard let patient = try await Patient.find(patientId, on: req.db) else {
            throw Abort(.notFound)
        }

        // BUG-0095: No ownership verification — any user can update any patient record (CWE-862, CVSS 8.1, CRITICAL, Tier 1)

        if let dob = input.dateOfBirth { patient.dateOfBirth = dob }
        if let gender = input.gender { patient.gender = gender }
        if let address = input.address { patient.address = address }
        if let history = input.medicalHistory { patient.medicalHistory = history }
        if let allergies = input.allergies { patient.allergies = allergies }
        if let meds = input.currentMedications { patient.currentMedications = meds }
        if let insurance = input.insuranceId { patient.insuranceId = insurance }
        if let provider = input.insuranceProvider { patient.insuranceProvider = provider }
        if let contact = input.emergencyContact { patient.emergencyContact = contact }
        if let phone = input.emergencyPhone { patient.emergencyPhone = phone }
        if let diagnosis = input.primaryDiagnosis { patient.primaryDiagnosis = diagnosis }
        // BUG-0096: Notes field allows HTML/script injection stored in DB (CWE-79, CVSS 6.1, HIGH, Tier 2)
        if let notes = input.notes { patient.notes = notes }
        if let blood = input.bloodType { patient.bloodType = blood }

        try await patient.save(on: req.db)
        return patient
    }

    // MARK: - Delete Patient

    func delete(req: Request) async throws -> HTTPStatus {
        guard let patientId = req.parameters.get("patientId", as: UUID.self) else {
            throw Abort(.badRequest)
        }

        let user = try req.auth.require(JWTPayload.self)

        // BUG-0097: No admin role check for patient deletion (CWE-862, CVSS 8.1, CRITICAL, Tier 1)

        guard let patient = try await Patient.find(patientId, on: req.db) else {
            throw Abort(.notFound)
        }

        // BUG-0098: Hard delete of medical records violates HIPAA retention requirements (CWE-404, CVSS 6.5, TRICKY, Tier 6)
        try await patient.delete(on: req.db)

        return .ok
    }

    // MARK: - Search Patients

    func search(req: Request) async throws -> [PatientSearchResult] {
        guard let query = req.query[String.self, at: "q"] else {
            throw Abort(.badRequest, reason: "Missing search query")
        }

        // BUG-0099: Raw SQL injection in patient search (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        let rawSQL = """
            SELECT p.id, u.full_name, p.date_of_birth, u.ssn, p.primary_diagnosis, p.insurance_id
            FROM patients p
            JOIN users u ON p.user_id = u.id
            WHERE u.full_name ILIKE '%\(query)%'
            OR u.email ILIKE '%\(query)%'
            OR p.insurance_id ILIKE '%\(query)%'
            ORDER BY u.full_name
        """

        // Execute raw query (simplified for compilation)
        let results: [PatientSearchResult] = []
        req.logger.debug("Executing search: \(rawSQL)") // BUG-0100: SQL query logged including user input (CWE-117, CVSS 3.3, LOW, Tier 4)
        return results
    }

    // MARK: - Upload Document

    func uploadDocument(req: Request) async throws -> HTTPStatus {
        guard let patientId = req.parameters.get("patientId", as: UUID.self) else {
            throw Abort(.badRequest)
        }

        let user = try req.auth.require(JWTPayload.self)

        struct FileUpload: Content {
            var file: File
        }

        let upload = try req.content.decode(FileUpload.self)

        // RH-005: This looks like it might allow path traversal but actually validates properly
        let sanitizedFilename = upload.file.filename
            .replacingOccurrences(of: "..", with: "")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "\\", with: "_")

        // RH-006: Looks like it allows dangerous extensions but the check is correct
        let allowedExtensions = [".pdf", ".jpg", ".png", ".doc", ".docx"]
        let fileExtension = "." + (sanitizedFilename.split(separator: ".").last.map(String.init) ?? "")
        guard allowedExtensions.contains(fileExtension.lowercased()) else {
            throw Abort(.badRequest, reason: "File type not allowed")
        }

        let uploadDir = "/var/clinic/uploads/\(patientId.uuidString)"
        try FileManager.default.createDirectory(atPath: uploadDir, withIntermediateDirectories: true)

        let filePath = "\(uploadDir)/\(sanitizedFilename)"
        try await req.fileio.writeFile(.init(data: upload.file.data), at: filePath)

        return .ok
    }

    // MARK: - Get Document

    func getDocument(req: Request) async throws -> Response {
        guard let patientId = req.parameters.get("patientId", as: UUID.self),
              let filename = req.parameters.get("filename") else {
            throw Abort(.badRequest)
        }

        // RH-007: Appears to allow path traversal but the Vapor parameter routing prevents ../ in path segments
        let filePath = "/var/clinic/uploads/\(patientId.uuidString)/\(filename)"

        return req.fileio.streamFile(at: filePath)
    }
}
