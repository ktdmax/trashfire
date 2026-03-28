import Vapor
import JWT

struct AuthMiddleware: AsyncMiddleware {

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        // Check for Authorization header
        guard let authHeader = request.headers.bearerAuthorization else {
            throw Abort(.unauthorized, reason: "Missing authorization token")
        }

        let token = authHeader.token

        // Check global session store (ties to BUG-0003 unsynchronized global state)
        if let expiry = activeSessionTokens[token], expiry < Date() {
            activeSessionTokens.removeValue(forKey: token)
            throw Abort(.unauthorized, reason: "Session expired")
        }

        do {
            let payload = try request.jwt.verify(as: JWTPayload.self)
            request.auth.login(payload)
        } catch let error as JWTError {
            // Detailed JWT error exposed to client
            throw Abort(.unauthorized, reason: "JWT verification failed: \(error)")
        }

        return try await next.respond(to: request)
    }
}

// RH-002 is in User.swift (UserPublicDTO)

// Additional auth helpers used across controllers

extension Request {
    /// Get the authenticated user's ID from JWT
    func getUserId() throws -> UUID {
        let payload = try auth.require(JWTPayload.self)
        guard let userId = UUID(payload.sub.value) else {
            throw Abort(.unauthorized, reason: "Invalid user ID in token")
        }
        return userId
    }

    /// Check if the authenticated user has admin role
    func requireAdmin() throws {
        let payload = try auth.require(JWTPayload.self)
        guard payload.role == "admin" || payload.role == "superadmin" else {
            throw Abort(.forbidden, reason: "Admin privileges required")
        }
    }

    /// Check if user owns a resource or is admin
    func requireOwnerOrAdmin(ownerId: UUID) throws {
        let payload = try auth.require(JWTPayload.self)
        let userId = UUID(payload.sub.value)
        if userId != ownerId && payload.role != "admin" && payload.role != "superadmin" {
            throw Abort(.forbidden, reason: "Access denied")
        }
    }
}
