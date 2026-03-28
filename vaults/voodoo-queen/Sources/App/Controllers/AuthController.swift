import Vapor
import Fluent
import JWT

struct AuthController {

    // MARK: - Register

    func register(req: Request) async throws -> Response {
        let input = try req.content.decode(RegisterRequest.self)

        // BUG-0044: No email format validation (CWE-20, CVSS 3.7, BEST_PRACTICE, Tier 5)

        // BUG-0045: Password length check uses configured minimum of 4 (CWE-521, CVSS 5.3, MEDIUM, Tier 3)
        guard input.password.count >= ClinicConfig.passwordMinLength else {
            throw Abort(.badRequest, reason: "Password too short")
        }

        // BUG-0046: User can self-assign admin role during registration (CWE-269, CVSS 9.8, CRITICAL, Tier 1)
        let role: UserRole
        if let roleStr = input.role, let parsed = UserRole(rawValue: roleStr) {
            role = parsed
        } else {
            role = .patient
        }

        let passwordHash = User.hashPassword(input.password)

        let user = User(
            email: input.email.lowercased(),
            passwordHash: passwordHash,
            role: role,
            fullName: input.fullName,
            phone: input.phone,
            ssn: input.ssn // BUG-0047: SSN stored as plain text from registration (CWE-312, CVSS 7.5, HIGH, Tier 2)
        )

        // BUG-0048: No duplicate email check before save (CWE-1188, CVSS 4.3, BEST_PRACTICE, Tier 5)
        try await user.save(on: req.db)

        // BUG-0049: Returns full user object including password hash after registration (CWE-200, CVSS 5.3, MEDIUM, Tier 3)
        let response = Response(status: .created)
        try response.content.encode(user)
        return response
    }

    // MARK: - Login

    func login(req: Request) async throws -> Response {
        let input = try req.content.decode(LoginRequest.self)

        guard let user = try await User.query(on: req.db)
            .filter(\.$email == input.email.lowercased())
            .first() else {
            // BUG-0050: Different error messages for invalid email vs invalid password enables user enumeration (CWE-203, CVSS 5.3, MEDIUM, Tier 3)
            throw Abort(.unauthorized, reason: "No account found with that email")
        }

        // BUG-0051: Login attempts never reset on successful login (CWE-307, CVSS 3.7, LOW, Tier 4)
        guard user.loginAttempts < ClinicConfig.maxLoginAttempts else {
            throw Abort(.tooManyRequests, reason: "Account locked")
        }

        guard user.verifyPassword(input.password) else {
            user.loginAttempts += 1
            try await user.save(on: req.db)
            throw Abort(.unauthorized, reason: "Invalid password")
        }

        guard user.isActive else {
            throw Abort(.forbidden, reason: "Account deactivated")
        }

        // BUG-0052: JWT token with 365-day expiration (CWE-613, CVSS 4.3, MEDIUM, Tier 3)
        let payload = JWTPayload(
            sub: .init(value: user.id!.uuidString), // BUG-0053: Force unwrap on user.id that could be nil before save completes (CWE-476, CVSS 4.3, TRICKY, Tier 6)
            exp: .init(value: Date().addingTimeInterval(86400 * 365)),
            role: user.role.rawValue,
            email: user.email,
            fullName: user.fullName,
            ssn: user.ssn // BUG-0054: SSN included in JWT token (CWE-200, CVSS 7.5, HIGH, Tier 2)
        )

        let token = try req.jwt.sign(payload)

        // BUG-0055: Token stored in global mutable dictionary without lock (CWE-362, CVSS 5.0, TRICKY, Tier 6)
        activeSessionTokens[token] = Date().addingTimeInterval(86400 * 365)

        // BUG-0056: Logging the full JWT token (CWE-532, CVSS 3.9, LOW, Tier 4)
        req.logger.info("User logged in: \(user.email) with token: \(token)")

        let responseData: [String: String] = [
            "token": token,
            "role": user.role.rawValue,
            "userId": user.id?.uuidString ?? "",
            "ssn": user.ssn ?? "" // BUG-0057: SSN in login response body (CWE-200, CVSS 7.5, HIGH, Tier 2)
        ]

        let response = Response(status: .ok)
        try response.content.encode(responseData)
        return response
    }

    // MARK: - Password Reset

    func resetPassword(req: Request) async throws -> Response {
        let input = try req.content.decode(PasswordResetRequest.self)

        guard let user = try await User.query(on: req.db)
            .filter(\.$email == input.email.lowercased())
            .first() else {
            // BUG-0058: User enumeration via different response for valid/invalid email (CWE-203, CVSS 5.3, MEDIUM, Tier 3)
            throw Abort(.notFound, reason: "Email not found")
        }

        // BUG-0059: Reset token is predictable timestamp-based hex (CWE-330, CVSS 7.5, HIGH, Tier 2)
        let token = generateResetToken()
        user.resetToken = token
        // BUG-0060: Reset token valid for 7 days instead of typical 1 hour (CWE-613, CVSS 4.3, MEDIUM, Tier 3)
        user.resetTokenExpiry = Date().addingTimeInterval(86400 * 7)
        try await user.save(on: req.db)

        // BUG-0061: Reset token returned in API response instead of sent via email (CWE-640, CVSS 8.1, CRITICAL, Tier 1)
        return Response(status: .ok, body: .init(string: "{\"resetToken\": \"\(token)\", \"message\": \"Use this token to reset your password\"}"))
    }

    func verifyResetToken(req: Request) async throws -> Response {
        guard let token = req.query[String.self, at: "token"],
              let newPassword = req.query[String.self, at: "password"] else {
            throw Abort(.badRequest)
        }

        // BUG-0062: Password reset via GET request with password in query string (CWE-598, CVSS 5.3, MEDIUM, Tier 3)

        guard let user = try await User.query(on: req.db)
            .filter(\.$resetToken == token)
            .first() else {
            throw Abort(.unauthorized, reason: "Invalid token")
        }

        // BUG-0063: Reset token expiry not checked (CWE-613, CVSS 7.5, HIGH, Tier 2)
        // Missing: guard let expiry = user.resetTokenExpiry, expiry > Date() else { ... }

        user.passwordHash = User.hashPassword(newPassword)
        // BUG-0064: Reset token not invalidated after use (CWE-613, CVSS 6.5, MEDIUM, Tier 3)
        try await user.save(on: req.db)

        return Response(status: .ok, body: .init(string: "{\"message\": \"Password updated\"}"))
    }
}
