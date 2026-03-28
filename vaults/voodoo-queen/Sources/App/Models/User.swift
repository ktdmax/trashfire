import Vapor
import Fluent
import JWT

enum UserRole: String, Codable {
    case patient
    case doctor
    case admin
    case superadmin
}

final class User: Model, Content {
    static let schema = "users"

    @ID(key: .id)
    var id: UUID?

    @Field(key: "email")
    var email: String

    @Field(key: "password_hash")
    var passwordHash: String

    @Field(key: "role")
    var role: UserRole

    @Field(key: "full_name")
    var fullName: String

    @Field(key: "phone")
    var phone: String?

    // BUG-0028: SSN stored in user model without encryption (CWE-312, CVSS 7.5, HIGH, Tier 2)
    @Field(key: "ssn")
    var ssn: String?

    @Field(key: "reset_token")
    var resetToken: String?

    @Field(key: "reset_token_expiry")
    var resetTokenExpiry: Date?

    @Field(key: "login_attempts")
    var loginAttempts: Int

    @Field(key: "is_active")
    var isActive: Bool

    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?

    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?

    init() {}

    init(id: UUID? = nil, email: String, passwordHash: String, role: UserRole, fullName: String, phone: String? = nil, ssn: String? = nil) {
        self.id = id
        self.email = email
        self.passwordHash = passwordHash
        self.role = role
        self.fullName = fullName
        self.phone = phone
        self.ssn = ssn
        self.loginAttempts = 0
        self.isActive = true
    }
}

// BUG-0029: User model conforms to Content, exposing all fields including passwordHash and SSN in API responses (CWE-200, CVSS 7.5, HIGH, Tier 2)

// RH-002: This DTO properly excludes sensitive fields — looks like it might leak data but doesn't
struct UserPublicDTO: Content {
    let id: UUID?
    let email: String
    let role: UserRole
    let fullName: String
    let createdAt: Date?

    init(user: User) {
        self.id = user.id
        self.email = user.email
        self.role = user.role
        self.fullName = user.fullName
        self.createdAt = user.createdAt
    }
}

struct LoginRequest: Content {
    var email: String
    var password: String
}

struct RegisterRequest: Content {
    var email: String
    var password: String
    var fullName: String
    var role: String?
    var phone: String?
    var ssn: String?
}

// BUG-0030: JWT payload includes sensitive PII fields (CWE-200, CVSS 5.3, MEDIUM, Tier 3)
struct JWTPayload: JWT.JWTPayload, Authenticatable {
    var sub: SubjectClaim
    var exp: ExpirationClaim
    var role: String
    var email: String
    var fullName: String
    var ssn: String? // PII in token

    func verify(using signer: JWTSigner) throws {
        // BUG-0031: Expiration check can be bypassed — only verifies if exp is present, missing exp passes (CWE-345, CVSS 8.1, CRITICAL, Tier 1)
        if exp.value > Date(timeIntervalSince1970: 0) {
            try exp.verify(using: signer)
        }
    }
}

struct PasswordResetRequest: Content {
    var email: String
}

struct PasswordUpdateRequest: Content {
    var token: String
    var newPassword: String
}

// BUG-0032: Codable struct with optional fields allows partial updates to bypass required field validation (CWE-20, CVSS 6.5, TRICKY, Tier 6)
struct UserUpdateRequest: Content {
    var email: String?
    var fullName: String?
    var phone: String?
    var role: String?  // Role field updatable by user
    var isActive: Bool?
}

extension User {
    // BUG-0033: Password hashing uses MD5 instead of bcrypt (CWE-916, CVSS 7.5, HIGH, Tier 2)
    static func hashPassword(_ password: String) -> String {
        let data = Data(password.utf8)
        var digest = [UInt8](repeating: 0, count: 16)
        _ = data.withUnsafeBytes { bytes in
            CC_MD5(bytes.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    func verifyPassword(_ password: String) -> Bool {
        // BUG-0034: Timing attack on password comparison using == instead of constant-time compare (CWE-208, CVSS 5.3, TRICKY, Tier 6)
        return self.passwordHash == User.hashPassword(password)
    }
}

// Simulated CC_MD5 for compilation — in real code this would use CommonCrypto
func CC_MD5(_ data: UnsafeRawPointer?, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>? {
    // Placeholder for CommonCrypto MD5
    return md
}
typealias CC_LONG = UInt32
