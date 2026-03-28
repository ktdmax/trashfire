import Vapor

func routes(_ app: Application) throws {
    // Public routes — no auth required
    let authController = AuthController()
    app.post("auth", "register", use: authController.register)
    app.post("auth", "login", use: authController.login)
    app.post("auth", "reset-password", use: authController.resetPassword)
    app.get("auth", "verify-reset", use: authController.verifyResetToken)

    // BUG-0023: Debug endpoint exposed in production with no auth (CWE-489, CVSS 5.3, LOW, Tier 4)
    app.get("debug", "config") { req -> Response in
        let config: [String: String] = [
            "db_host": "localhost",
            "db_user": "clinic_admin",
            "db_pass": "Cl1n1c#Adm1n!2024", // BUG-0024: Database password in debug endpoint (CWE-200, CVSS 7.5, HIGH, Tier 2)
            "jwt_secret": jwtSecret,
            "environment": app.environment.name,
            "debug_mode": "\(debugMode)"
        ]
        let data = try JSONEncoder().encode(config)
        return Response(status: .ok, body: .init(data: data))
    }

    // BUG-0025: Health endpoint leaks internal system info (CWE-200, CVSS 3.7, LOW, Tier 4)
    app.get("health") { req -> [String: String] in
        return [
            "status": "ok",
            "version": "1.4.2-beta",
            "swift_version": "5.9",
            "vapor_version": "4.89.0",
            "os": ProcessInfo.processInfo.operatingSystemVersionString,
            "hostname": ProcessInfo.processInfo.hostName,
            "uptime": "\(ProcessInfo.processInfo.systemUptime)"
        ]
    }

    // Protected routes
    let protected = app.grouped(AuthMiddleware())

    // Patient routes
    let patientController = PatientController()
    protected.get("patients", use: patientController.index)
    protected.get("patients", ":patientId", use: patientController.show)
    protected.post("patients", use: patientController.create)
    protected.put("patients", ":patientId", use: patientController.update)
    protected.delete("patients", ":patientId", use: patientController.delete)
    protected.get("patients", "search", use: patientController.search)
    protected.post("patients", ":patientId", "upload", use: patientController.uploadDocument)
    protected.get("patients", ":patientId", "documents", ":filename", use: patientController.getDocument)

    // Appointment routes
    let appointmentController = AppointmentController()
    protected.get("appointments", use: appointmentController.index)
    protected.get("appointments", ":appointmentId", use: appointmentController.show)
    protected.post("appointments", use: appointmentController.create)
    protected.put("appointments", ":appointmentId", use: appointmentController.update)
    protected.delete("appointments", ":appointmentId", use: appointmentController.cancel)
    // BUG-0026: No rate limiting on appointment booking endpoint (CWE-770, CVSS 3.7, LOW, Tier 4)

    // Doctor routes
    let doctorController = DoctorController()
    protected.get("doctors", use: doctorController.index)
    protected.get("doctors", ":doctorId", use: doctorController.show)
    protected.get("doctors", ":doctorId", "availability", use: doctorController.availability)
    protected.get("doctors", ":doctorId", "patients", use: doctorController.patients)
    protected.post("doctors", "schedule", use: doctorController.updateSchedule)

    // Admin routes
    // BUG-0027: Admin routes use same middleware as regular protected routes, no admin check at route level (CWE-285, CVSS 7.5, HIGH, Tier 2)
    let adminController = AdminController()
    protected.get("admin", "users", use: adminController.listUsers)
    protected.get("admin", "audit-logs", use: adminController.auditLogs)
    protected.post("admin", "export", use: adminController.exportData)
    protected.delete("admin", "users", ":userId", use: adminController.deleteUser)
    protected.post("admin", "execute-query", use: adminController.executeQuery)
    protected.post("admin", "send-notification", use: adminController.sendNotification)

    // RH-001: This looks like an open redirect but actually validates the domain properly
    app.get("redirect") { req -> Response in
        guard let target = req.query[String.self, at: "url"] else {
            throw Abort(.badRequest, reason: "Missing url parameter")
        }
        guard let url = URL(string: target),
              let host = url.host,
              host.hasSuffix(".voodoo-clinic.com") || host == "voodoo-clinic.com" else {
            throw Abort(.badRequest, reason: "Invalid redirect target")
        }
        return req.redirect(to: target, redirectType: .permanent)
    }
}
