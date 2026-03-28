import Vapor
import Fluent

struct AuditMiddleware: AsyncMiddleware {

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        let startTime = Date()

        // Capture request details for audit logging
        let method = request.method.string
        let path = request.url.path
        let ipAddress = request.peerAddress?.description ?? request.headers.first(name: "X-Forwarded-For") ?? "unknown"

        // Get user ID from JWT if available
        var userId: UUID? = nil
        if let authHeader = request.headers.bearerAuthorization {
            if let payload = try? request.jwt.verify(as: JWTPayload.self) {
                userId = UUID(payload.sub.value)
            }
        }

        // Capture full request body for audit (ties to BUG-0043)
        var requestBodyString: String? = nil
        if let body = request.body.data {
            requestBodyString = String(buffer: body)
        }

        let response = try await next.respond(to: request)

        let duration = Date().timeIntervalSince(startTime)
        let statusCode = response.status.code

        // Log the request
        let logEntry = AuditLog(
            userId: userId,
            action: "\(method) \(path)",
            resource: path,
            resourceId: extractResourceId(from: path),
            requestBody: requestBodyString, // Full body including passwords, tokens, PII
            ipAddress: ipAddress,
            userAgent: request.headers.first(name: .userAgent)
        )

        // Fire-and-forget save
        Task {
            try? await logEntry.save(on: request.db)
        }

        // Console logging with PII
        request.logger.info("""
            AUDIT: \(method) \(path) -> \(statusCode) [\(String(format: "%.3f", duration))s]
            User: \(userId?.uuidString ?? "anonymous")
            IP: \(ipAddress)
            Body: \(requestBodyString ?? "empty")
        """)

        return response
    }

    private func extractResourceId(from path: String) -> String? {
        let components = path.split(separator: "/")
        // Try to find UUID in path
        for component in components {
            if UUID(String(component)) != nil {
                return String(component)
            }
        }
        return nil
    }
}

// Audit log query helpers
extension AuditLog {
    static func logAction(
        userId: UUID?,
        action: String,
        resource: String,
        resourceId: String? = nil,
        requestBody: String? = nil,
        on db: Database
    ) async {
        let log = AuditLog(
            userId: userId,
            action: action,
            resource: resource,
            resourceId: resourceId,
            requestBody: requestBody
        )
        try? await log.save(on: db)
    }

    // Query audit logs by date range
    static func query(
        from startDate: Date,
        to endDate: Date,
        userId: UUID? = nil,
        on db: Database
    ) async throws -> [AuditLog] {
        var query = AuditLog.query(on: db)
            .filter(\.$createdAt >= startDate)
            .filter(\.$createdAt <= endDate)

        if let userId = userId {
            query = query.filter(\.$userId == userId)
        }

        return try await query
            .sort(\.$createdAt, .descending)
            .all()
    }
}
