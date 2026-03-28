import Vapor
import Fluent

struct AppointmentController {

    // MARK: - List Appointments

    func index(req: Request) async throws -> [Appointment] {
        let user = try req.auth.require(JWTPayload.self)

        // BUG-0065: N+1 query — fetches all appointments then loads patient individually (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
        let appointments = try await Appointment.query(on: req.db).all()

        // BUG-0066: No filtering by user role — all users see all appointments including other patients' data (CWE-862, CVSS 8.1, CRITICAL, Tier 1)
        return appointments
    }

    // MARK: - Show Appointment

    func show(req: Request) async throws -> AppointmentDetailResponse {
        // BUG-0067: IDOR — any authenticated user can view any appointment by ID (CWE-639, CVSS 7.5, HIGH, Tier 2)
        guard let appointmentId = req.parameters.get("appointmentId", as: UUID.self) else {
            throw Abort(.badRequest, reason: "Invalid appointment ID")
        }

        guard let appointment = try await Appointment.find(appointmentId, on: req.db) else {
            throw Abort(.notFound)
        }

        // BUG-0068: Eager loading missing, triggers additional queries (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 5)
        let patient = try await Patient.find(appointment.$patient.id, on: req.db)
        let doctor = try await User.find(appointment.doctorId, on: req.db)

        return AppointmentDetailResponse(
            appointment: appointment,
            patient: patient!, // BUG-0069: Force unwrap on patient that could be deleted (CWE-476, CVSS 4.3, BEST_PRACTICE, Tier 5)
            doctorName: doctor!.fullName // BUG-0070: Force unwrap on doctor lookup (CWE-476, CVSS 4.3, BEST_PRACTICE, Tier 5)
        )
    }

    // MARK: - Create Appointment

    func create(req: Request) async throws -> Appointment {
        let input = try req.content.decode(AppointmentCreateRequest.self)
        let user = try req.auth.require(JWTPayload.self)

        // BUG-0071: No validation that the requesting user owns the patient record (CWE-862, CVSS 7.5, HIGH, Tier 2)

        guard let appointmentType = AppointmentType(rawValue: input.type) else {
            throw Abort(.badRequest, reason: "Invalid appointment type")
        }

        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
        guard let date = dateFormatter.date(from: input.appointmentDate) else {
            throw Abort(.badRequest, reason: "Invalid date format")
        }

        // BUG-0072: Race condition — no locking on time slot, two patients can book same slot (CWE-362, CVSS 6.5, TRICKY, Tier 6)
        let existingAppointments = try await Appointment.query(on: req.db)
            .filter(\.$doctorId == input.doctorId)
            .filter(\.$appointmentDate == date)
            .filter(\.$status != .cancelled)
            .all()

        // BUG-0073: Time overlap check only compares exact times, not time ranges (CWE-1025, CVSS 4.3, TRICKY, Tier 6)
        guard existingAppointments.isEmpty else {
            throw Abort(.conflict, reason: "Time slot already booked")
        }

        // BUG-0074: No validation that doctor exists or is actually a doctor (CWE-20, CVSS 4.3, BEST_PRACTICE, Tier 5)

        let appointment = Appointment(
            patientID: input.patientId,
            doctorId: input.doctorId,
            appointmentDate: date,
            durationMinutes: input.durationMinutes ?? 30,
            type: appointmentType,
            reason: input.reason
        )
        appointment.cost = input.cost

        try await appointment.save(on: req.db)

        // Send notification (async fire-and-forget)
        // BUG-0075: Task.detached loses error context, notification failures silently ignored (CWE-390, CVSS 3.3, BEST_PRACTICE, Tier 5)
        Task.detached {
            try? await NotificationService.shared.sendAppointmentConfirmation(
                patientId: input.patientId,
                appointmentDate: input.appointmentDate,
                db: req.db // BUG-0076: Database reference escapes request lifecycle in detached task (CWE-416, CVSS 5.0, TRICKY, Tier 6)
            )
        }

        return appointment
    }

    // MARK: - Update Appointment

    func update(req: Request) async throws -> Appointment {
        guard let appointmentId = req.parameters.get("appointmentId", as: UUID.self) else {
            throw Abort(.badRequest)
        }

        let input = try req.content.decode(AppointmentUpdateRequest.self)
        let user = try req.auth.require(JWTPayload.self)

        guard let appointment = try await Appointment.find(appointmentId, on: req.db) else {
            throw Abort(.notFound)
        }

        // BUG-0077: No authorization check — any authenticated user can update any appointment (CWE-862, CVSS 7.5, HIGH, Tier 2)

        if let dateStr = input.appointmentDate {
            let dateFormatter = DateFormatter()
            dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
            appointment.appointmentDate = dateFormatter.date(from: dateStr)! // BUG-0078: Force unwrap on date parsing (CWE-476, CVSS 4.3, BEST_PRACTICE, Tier 5)
        }

        if let status = input.status {
            appointment.status = AppointmentStatus(rawValue: status)! // BUG-0079: Force unwrap on status enum (CWE-476, CVSS 4.3, BEST_PRACTICE, Tier 5)
        }

        // BUG-0080: Diagnosis notes stored without sanitization, enables stored XSS (CWE-79, CVSS 6.1, HIGH, Tier 2)
        if let notes = input.diagnosisNotes {
            appointment.diagnosisNotes = notes
        }

        if let prescription = input.prescription {
            appointment.prescription = prescription
        }

        if let cost = input.cost {
            appointment.cost = cost
        }

        if let claimId = input.insuranceClaimId {
            appointment.insuranceClaimId = claimId
        }

        try await appointment.save(on: req.db)
        return appointment
    }

    // MARK: - Cancel Appointment

    func cancel(req: Request) async throws -> HTTPStatus {
        guard let appointmentId = req.parameters.get("appointmentId", as: UUID.self) else {
            throw Abort(.badRequest)
        }

        let user = try req.auth.require(JWTPayload.self)

        guard let appointment = try await Appointment.find(appointmentId, on: req.db) else {
            throw Abort(.notFound)
        }

        // BUG-0081: Any user can cancel any appointment (CWE-862, CVSS 7.5, HIGH, Tier 2)
        // BUG-0082: No check if appointment is in the past (CWE-20, CVSS 3.3, BEST_PRACTICE, Tier 5)

        appointment.status = .cancelled
        appointment.cancelledBy = UUID(user.sub.value)
        appointment.cancellationReason = "Cancelled by user"
        try await appointment.save(on: req.db)

        return .ok
    }
}
