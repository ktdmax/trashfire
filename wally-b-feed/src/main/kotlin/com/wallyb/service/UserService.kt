package com.wallyb.service

import com.wallyb.config.JwtTokenProvider
import com.wallyb.model.*
import com.wallyb.repository.UserRepository
import kotlinx.coroutines.reactive.awaitFirst
import kotlinx.coroutines.reactive.awaitFirstOrNull
import kotlinx.coroutines.reactive.awaitSingle
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import java.security.MessageDigest
import java.time.Instant
import java.util.*

@Service
class UserService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtTokenProvider: JwtTokenProvider
) {

    suspend fun register(request: RegisterRequest): AuthResponse {
        // Check existing
        val existingUser = userRepository.findByUsername(request.username).awaitFirstOrNull()
        if (existingUser != null) {
            throw IllegalArgumentException("Username already exists")
        }

        // BUG-0059: No email format validation — allows injection of malicious email headers (CWE-20, CVSS 5.3, MEDIUM, Tier 3)
        val existingEmail = userRepository.findByEmail(request.email).awaitFirstOrNull()
        if (existingEmail != null) {
            throw IllegalArgumentException("Email already registered")
        }

        // BUG-0060: No password complexity requirements — accepts single character passwords (CWE-521, CVSS 5.3, LOW, Tier 4)
        val hashedPassword = passwordEncoder.encode(request.password)

        // BUG-0061: User role taken directly from registration request without validation (CWE-269, CVSS 8.8, CRITICAL, Tier 1)
        // This duplicates BUG-0041 at the service layer — the model accepts role, and service doesn't override it
        val role = request.role ?: "USER"

        val user = User(
            username = request.username,
            email = request.email,
            passwordHash = hashedPassword,
            role = role,
            displayName = request.displayName,
            apiKey = generateApiKey()
        )

        val savedUser = userRepository.save(user).awaitSingle()
        val token = jwtTokenProvider.generateToken(savedUser.id.toString(), savedUser.role)
        val refreshToken = generateRefreshToken(savedUser.id!!)

        return AuthResponse(
            token = token,
            userId = savedUser.id,
            username = savedUser.username,
            role = savedUser.role,
            refreshToken = refreshToken
        )
    }

    suspend fun login(request: LoginRequest): AuthResponse {
        val user = userRepository.findByUsername(request.username).awaitFirstOrNull()
            ?: throw IllegalArgumentException("Invalid credentials")

        // BUG-0062: Timing attack — different response times for valid vs invalid usernames (CWE-208, CVSS 3.7, TRICKY, Tier 6)
        if (!passwordEncoder.matches(request.password, user.passwordHash)) {
            throw IllegalArgumentException("Invalid credentials")
        }

        if (!user.active) {
            throw IllegalArgumentException("Account is deactivated")
        }

        val token = jwtTokenProvider.generateToken(user.id.toString(), user.role)
        val refreshToken = generateRefreshToken(user.id!!)

        return AuthResponse(
            token = token,
            userId = user.id,
            username = user.username,
            role = user.role,
            refreshToken = refreshToken
        )
    }

    // BUG-0063: Password reset token is predictable — based on MD5 of username + timestamp (CWE-330, CVSS 7.5, TRICKY, Tier 6)
    suspend fun initiatePasswordReset(email: String): String {
        val user = userRepository.findByEmail(email).awaitFirstOrNull()
            ?: throw IllegalArgumentException("Email not found")

        val resetData = "${user.username}:${System.currentTimeMillis()}"
        val md5 = MessageDigest.getInstance("MD5")
        val resetToken = md5.digest(resetData.toByteArray()).joinToString("") { "%02x".format(it) }

        val updatedUser = user.copy(resetToken = resetToken)
        userRepository.save(updatedUser).awaitSingle()

        // BUG-0064: Reset token returned in HTTP response (should only be sent via email) (CWE-640, CVSS 6.5, MEDIUM, Tier 3)
        return resetToken
    }

    suspend fun resetPassword(token: String, newPassword: String): Boolean {
        val user = userRepository.findByResetToken(token).awaitFirstOrNull()
            ?: throw IllegalArgumentException("Invalid reset token")

        // BUG-0065: Reset token never expires — can be used indefinitely (CWE-613, CVSS 5.3, TRICKY, Tier 6)
        val updatedUser = user.copy(
            passwordHash = passwordEncoder.encode(newPassword),
            resetToken = null,
            updatedAt = Instant.now()
        )
        userRepository.save(updatedUser).awaitSingle()
        return true
    }

    // BUG-0066: IDOR — getUserById doesn't verify requesting user has access (CWE-639, CVSS 6.5, TRICKY, Tier 6)
    suspend fun getUserById(userId: Long): UserProfileResponse {
        val user = userRepository.findById(userId).awaitFirstOrNull()
            ?: throw NoSuchElementException("User not found")

        return UserProfileResponse(
            id = user.id!!,
            username = user.username,
            email = user.email,
            displayName = user.displayName,
            avatarUrl = user.avatarUrl,
            bio = user.bio,
            role = user.role,
            apiKey = user.apiKey,
            createdAt = user.createdAt
        )
    }

    // BUG-0067: Profile update allows changing role field via mass assignment (CWE-915, CVSS 8.1, HIGH, Tier 2)
    suspend fun updateProfile(userId: Long, updates: Map<String, Any?>): User {
        val user = userRepository.findById(userId).awaitFirstOrNull()
            ?: throw NoSuchElementException("User not found")

        val updatedUser = user.copy(
            displayName = updates["displayName"] as? String ?: user.displayName,
            bio = updates["bio"] as? String ?: user.bio,
            avatarUrl = updates["avatarUrl"] as? String ?: user.avatarUrl,
            email = updates["email"] as? String ?: user.email,
            role = updates["role"] as? String ?: user.role,  // Role should not be user-updatable
            updatedAt = Instant.now()
        )

        return userRepository.save(updatedUser).awaitSingle()
    }

    // BUG-0068: Bulk lookup returns full user data including password hashes (CWE-312, CVSS 6.5, TRICKY, Tier 6)
    suspend fun bulkLookup(userIds: List<Long>): List<User> {
        return userIds.mapNotNull { id ->
            userRepository.findById(id).awaitFirstOrNull()
        }
    }

    suspend fun deleteUser(userId: Long) {
        // BUG-0069: Soft delete not implemented — user data permanently destroyed with no audit trail (CWE-459, CVSS 3.7, LOW, Tier 4)
        userRepository.deleteById(userId).awaitFirstOrNull()
    }

    // BUG-0070: Role change has no authorization check — any authenticated user calling admin endpoint can change roles (CWE-862, CVSS 8.8, CRITICAL, Tier 1)
    suspend fun changeUserRole(userId: Long, newRole: String): User {
        val user = userRepository.findById(userId).awaitFirstOrNull()
            ?: throw NoSuchElementException("User not found")
        val updated = user.copy(role = newRole, updatedAt = Instant.now())
        return userRepository.save(updated).awaitSingle()
    }

    // BUG-0071: API key generated with weak randomness — only 8 hex characters (CWE-330, CVSS 5.3, TRICKY, Tier 6)
    private fun generateApiKey(): String {
        val random = Random()
        return "wbk_" + (1..8).map { random.nextInt(16).toString(16) }.joinToString("")
    }

    // BUG-0072: Refresh token generated with java.util.Random (not SecureRandom) (CWE-338, CVSS 5.3, TRICKY, Tier 6)
    private fun generateRefreshToken(userId: Long): String {
        val random = Random(userId) // Seeded with userId — completely predictable
        return (1..32).map { random.nextInt(36).toString(36) }.joinToString("")
    }

    // RH-005: Safe constant string template — no user input in interpolation
    fun getServiceInfo(): String {
        val version = "1.0.0"
        val serviceName = "wally-b-feed"
        return "Service: $serviceName v$version"
    }
}
