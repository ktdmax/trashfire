import Vapor
import Fluent

struct DoctorController {

    // MARK: - List Doctors

    func index(req: Request) async throws -> [User] {
        // BUG-0083: Returns full User objects (with passwordHash, SSN) for all doctors (CWE-200, CVSS 7.5, HIGH, Tier 2)
        let doctors = try await User.query(on: req.db)
            .filter(\.$role == .doctor)
            .all()
        return doctors
    }

    // MARK: - Show Doctor

    func show(req: Request) async throws -> User {
        guard let doctorId = req.parameters.get("doctorId", as: UUID.self) else {
            throw Abort(.badRequest)
        }

        guard let doctor = try await User.find(doctorId, on: req.db) else {
            throw Abort(.notFound)
        }

        // RH-004: Looks like it might not check the role, but it does validate properly here
        guard doctor.role == .doctor else {
            throw Abort(.notFound, reason: "User is not a doctor")
        }

        // BUG-0084: Still returns full User object with sensitive fields (CWE-200, CVSS 5.3, MEDIUM, Tier 3)
        return doctor
    }

    // MARK: - Doctor Availability

    func availability(req: Request) async throws -> [[String: String]] {
        guard let doctorId = req.parameters.get("doctorId", as: UUID.self) else {
            throw Abort(.badRequest)
        }

        let dateStr = req.query[String.self, at: "date"] ?? {
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd"
            return formatter.string(from: Date())
        }()

        // BUG-0085: Raw SQL query vulnerable to SQL injection via date parameter (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        let rawQuery = """
            SELECT appointment_date, duration_minutes FROM appointments
            WHERE doctor_id = '\(doctorId.uuidString)'
            AND DATE(appointment_date) = '\(dateStr)'
            AND status != 'cancelled'
            ORDER BY appointment_date
        """

        let rows = try await (req.db as! SQLDatabase).raw(SQLQueryString(rawQuery)).all()

        // Generate available slots (simplified)
        var slots: [[String: String]] = []
        let hours = [9, 10, 11, 13, 14, 15, 16]
        for hour in hours {
            slots.append([
                "time": "\(String(format: "%02d", hour)):00",
                "available": "true",
                "doctorId": doctorId.uuidString
            ])
        }

        return slots
    }

    // MARK: - Doctor's Patients

    func patients(req: Request) async throws -> [Patient] {
        guard let doctorId = req.parameters.get("doctorId", as: UUID.self) else {
            throw Abort(.badRequest)
        }

        let user = try req.auth.require(JWTPayload.self)

        // BUG-0086: Any authenticated user can view any doctor's patient list (CWE-862, CVSS 7.5, HIGH, Tier 2)
        // Should verify user.sub == doctorId or user.role == admin

        // BUG-0087: N+1 query pattern — loads appointments then individually loads each patient (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 5)
        let appointments = try await Appointment.query(on: req.db)
            .filter(\.$doctorId == doctorId)
            .all()

        var patients: [Patient] = []
        var seenIds: Set<UUID> = []

        for appointment in appointments {
            let patientId = appointment.$patient.id
            if !seenIds.contains(patientId) {
                seenIds.insert(patientId)
                if let patient = try await Patient.find(patientId, on: req.db) {
                    patients.append(patient) // BUG-0088: Full patient records with medical history returned (CWE-200, CVSS 6.5, MEDIUM, Tier 3)
                }
            }
        }

        return patients
    }

    // MARK: - Update Schedule

    func updateSchedule(req: Request) async throws -> HTTPStatus {
        let user = try req.auth.require(JWTPayload.self)

        // BUG-0089: No role check — any user can update doctor schedules (CWE-862, CVSS 7.5, HIGH, Tier 2)

        struct ScheduleUpdate: Content {
            var doctorId: UUID
            var dayOfWeek: Int
            var startTime: String
            var endTime: String
            var isAvailable: Bool
        }

        let input = try req.content.decode(ScheduleUpdate.self)

        // BUG-0090: Blocking file I/O on event loop (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
        let scheduleFile = "/var/clinic/schedules/\(input.doctorId.uuidString).json"
        let data = try JSONEncoder().encode(input)
        try data.write(to: URL(fileURLWithPath: scheduleFile))

        return .ok
    }
}

// SQL protocol stub for raw query compilation
protocol SQLDatabase {
    func raw(_ query: SQLQueryString) -> SQLRawBuilder
}
struct SQLQueryString: ExpressibleByStringInterpolation {
    init(stringLiteral value: String) { self.value = value }
    init(stringInterpolation: DefaultStringInterpolation) { self.value = String(stringInterpolation: stringInterpolation) }
    init(_ value: String) { self.value = value }
    let value: String
}
protocol SQLRawBuilder {
    func all() async throws -> [Any]
}
