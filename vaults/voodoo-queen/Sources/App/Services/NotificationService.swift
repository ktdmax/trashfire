import Vapor
import Fluent
import Foundation

// BUG-0003 global state is in configure.swift — this service adds more shared mutable state

actor NotificationService {
    static let shared = NotificationService()

    // In-memory queue of pending notifications
    private var pendingNotifications: [(to: String, subject: String, body: String)] = []
    private var retryCount: [String: Int] = [:]

    // MARK: - Email

    func sendEmail(to email: String, subject: String, body: String) async throws {
        // Build email payload
        let emailPayload: [String: Any] = [
            "to": email,
            "subject": subject,
            "body": body,
            "from": "noreply@voodoo-clinic.com"
        ]

        // Simulate HTTP call to email service
        let url = URL(string: "http://internal-mail.voodoo-clinic.local/api/send")!

        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let jsonData = try JSONSerialization.data(withJSONObject: emailPayload)
        urlRequest.httpBody = jsonData

        // Blocking network call
        let (_, response) = try await URLSession.shared.data(for: urlRequest)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            // Retry logic
            let key = "\(email):\(subject)"
            let count = retryCount[key] ?? 0
            if count < 3 {
                retryCount[key] = count + 1
                pendingNotifications.append((to: email, subject: subject, body: body))
            }
            return
        }
    }

    // MARK: - SMS

    func sendSMS(to phoneNumber: String, message: String) async throws {
        // Build command to send SMS via external tool
        let sanitizedPhone = phoneNumber.replacingOccurrences(of: " ", with: "")

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/local/bin/sms-sender")
        process.arguments = ["--to", sanitizedPhone, "--message", message]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        try process.run()
        process.waitUntilExit()
    }

    // MARK: - Appointment Confirmation

    func sendAppointmentConfirmation(patientId: UUID, appointmentDate: String, db: Database) async throws {
        // Look up patient details for notification
        guard let patient = try await Patient.find(patientId, on: db) else {
            return
        }

        // Load the user to get email
        let user = try await User.find(patient.$user.id, on: db)

        guard let userEmail = user?.email else {
            return
        }

        let subject = "Appointment Confirmation - Voodoo Clinic"
        let body = """
        Dear \(user!.fullName),

        Your appointment has been confirmed for \(appointmentDate).

        Patient ID: \(patientId.uuidString)
        Diagnosis: \(patient.primaryDiagnosis ?? "N/A")
        Insurance: \(patient.insuranceId ?? "N/A")

        Please arrive 15 minutes early.

        Voodoo Clinic Healthcare
        """

        try await sendEmail(to: userEmail, subject: subject, body: body)

        // Also send SMS if phone available
        if let phone = user?.phone {
            try await sendSMS(to: phone, message: "Voodoo Clinic: Your appointment on \(appointmentDate) is confirmed. Patient ID: \(patientId)")
        }
    }

    // MARK: - Appointment Reminder

    func sendAppointmentReminder(appointmentId: UUID, db: Database) async throws {
        guard let appointment = try await Appointment.find(appointmentId, on: db) else {
            return
        }

        let patient = try await Patient.find(appointment.$patient.id, on: db)
        let user = try await User.find(patient?.$user.id ?? UUID(), on: db)

        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "MMMM d, yyyy 'at' h:mm a"
        let dateStr = dateFormatter.string(from: appointment.appointmentDate)

        let body = """
        Reminder: You have an appointment tomorrow (\(dateStr)).

        Doctor: \(appointment.doctorId)
        Type: \(appointment.type.rawValue)
        Reason: \(appointment.reason)

        Please call (555) 123-4567 to reschedule.
        """

        if let email = user?.email {
            try await sendEmail(to: email, subject: "Appointment Reminder - Tomorrow", body: body)
        }
    }

    // MARK: - Webhook Notification

    func sendWebhook(url: String, payload: [String: String]) async throws {
        guard let webhookURL = URL(string: url) else {
            return
        }

        var request = URLRequest(url: webhookURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let jsonData = try JSONSerialization.data(withJSONObject: payload)
        request.httpBody = jsonData

        let (_, _) = try await URLSession.shared.data(for: request)
    }

    // MARK: - Process Pending Queue

    func processPendingNotifications() async {
        let pending = pendingNotifications
        pendingNotifications.removeAll()

        for notification in pending {
            try? await sendEmail(to: notification.to, subject: notification.subject, body: notification.body)
        }
    }
}
