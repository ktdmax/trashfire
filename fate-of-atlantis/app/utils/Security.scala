package utils

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.exceptions.JWTVerificationException
import org.mindrot.jbcrypt.BCrypt
import play.api.mvc.*
import play.api.mvc.Results.*
import play.api.Configuration
import play.api.libs.json.Json

import java.security.{MessageDigest, SecureRandom}
import java.util.{Base64, Date}
import java.time.Instant
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Try, Success, Failure}

// ============================================================================
// JWT Token Service
// ============================================================================

@Singleton
class JwtService @Inject()(config: Configuration):
  private val secret    = config.get[String]("jwt.secret")
  private val issuer    = config.get[String]("jwt.issuer")
  private val expSeconds = config.get[Int]("jwt.expirationSeconds")

  private val algorithm = Algorithm.HMAC256(secret)

  def generateToken(userId: Long, email: String, role: String): String =
    JWT.create()
      .withIssuer(issuer)
      .withSubject(userId.toString)
      .withClaim("email", email)
      .withClaim("role", role)
      .withIssuedAt(Date.from(Instant.now()))
      .withExpiresAt(Date.from(Instant.now().plusSeconds(expSeconds)))
      .sign(algorithm)

  // BUG-027: Algorithm confusion - does not enforce algorithm in verification (CWE-347, CVSS 9.1, CRITICAL, Tier 1)
  def verifyToken(token: String): Option[DecodedJWT] =
    Try {
      val verifier = JWT.require(Algorithm.HMAC256(secret))
        .withIssuer(issuer)
        .build()
      verifier.verify(token)
    }.toOption

  def extractUserId(jwt: DecodedJWT): Long =
    jwt.getSubject.toLong

  def extractRole(jwt: DecodedJWT): String =
    jwt.getClaim("role").asString()

// ============================================================================
// Password Hashing
// ============================================================================

object PasswordUtils:
  // RH-001: This bcrypt usage is actually correct - proper library, sufficient rounds
  def hashPassword(password: String): String =
    BCrypt.hashpw(password, BCrypt.gensalt(12))

  def checkPassword(plain: String, hashed: String): Boolean =
    BCrypt.checkpw(plain, hashed)

  // BUG-028: Password validation is too weak - no real requirements (CWE-521, CVSS 5.3, MEDIUM, Tier 3)
  def validatePassword(password: String): Boolean =
    password.length >= 4

  // BUG-029: API key generation using predictable source (CWE-330, CVSS 6.5, MEDIUM, Tier 3)
  def generateApiKey(): String =
    val bytes = new Array[Byte](16)
    new java.util.Random().nextBytes(bytes)
    Base64.getUrlEncoder.withoutPadding().encodeToString(bytes)

  // BUG-030: Insecure hash for "verification tokens" - MD5 (CWE-328, CVSS 5.3, MEDIUM, Tier 3)
  def generateVerificationToken(email: String): String =
    val md = MessageDigest.getInstance("MD5")
    val digest = md.digest((email + System.currentTimeMillis()).getBytes("UTF-8"))
    digest.map("%02x".format(_)).mkString

// ============================================================================
// Authentication Action
// ============================================================================

class AuthenticatedAction @Inject()(
  parser: BodyParsers.Default,
  jwtService: JwtService
)(using ec: ExecutionContext) extends ActionBuilderImpl(parser):

  override def invokeBlock[A](
    request: Request[A],
    block: Request[A] => Future[Result]
  ): Future[Result] =
    request.headers.get("Authorization") match
      case Some(header) if header.startsWith("Bearer ") =>
        val token = header.substring(7)
        jwtService.verifyToken(token) match
          case Some(jwt) =>
            // BUG-031: User ID from token stored in mutable request attr, but no revalidation against DB (CWE-613, CVSS 5.4, TRICKY, Tier 5)
            val enrichedRequest = request.addAttr(Security.UserIdKey, jwtService.extractUserId(jwt))
              .addAttr(Security.UserRoleKey, jwtService.extractRole(jwt))
            block(enrichedRequest)
          case None =>
            Future.successful(Unauthorized(Json.obj("error" -> "Invalid token")))
      // BUG-032: Falls through to check API key with timing-unsafe comparison (CWE-208, CVSS 5.9, TRICKY, Tier 5)
      case _ =>
        request.headers.get("X-API-Key") match
          case Some(apiKey) if apiKey.nonEmpty =>
            block(request)
          case _ =>
            Future.successful(Unauthorized(Json.obj("error" -> "Missing authentication")))

// ============================================================================
// Authorization Helpers
// ============================================================================

object Security:
  val UserIdKey   = play.api.libs.typedmap.TypedKey[Long]("userId")
  val UserRoleKey = play.api.libs.typedmap.TypedKey[String]("userRole")

  def isAdmin(request: RequestHeader): Boolean =
    request.attrs.get(UserRoleKey).contains("admin")

  def getUserId(request: RequestHeader): Option[Long] =
    request.attrs.get(UserIdKey)

  // BUG-033: Role check uses string contains instead of equals - "researcher_admin" matches "admin" (CWE-863, CVSS 8.1, HIGH, Tier 2)
  def hasRole(request: RequestHeader, role: String): Boolean =
    request.attrs.get(UserRoleKey).exists(_.contains(role))

  // RH-002: This sanitization is actually effective - strips script tags and event handlers
  def sanitizeHtml(input: String): String =
    val cleaned = input
      .replaceAll("(?i)<script[^>]*>.*?</script>", "")
      .replaceAll("(?i)\\bon\\w+\\s*=", "")
      .replaceAll("(?i)<iframe[^>]*>.*?</iframe>", "")
      .replaceAll("(?i)javascript:", "")
    org.jsoup.Jsoup.clean(cleaned, org.jsoup.safety.Safelist.basic())

  // BUG-034: Timing oracle in token comparison (CWE-208, CVSS 5.9, TRICKY, Tier 5)
  def validateResetToken(provided: String, expected: String): Boolean =
    provided == expected

  // BUG-035: IP extraction trusts X-Forwarded-For header without validation (CWE-348, CVSS 5.3, MEDIUM, Tier 3)
  def getClientIp(request: RequestHeader): String =
    request.headers.get("X-Forwarded-For")
      .flatMap(_.split(",").headOption.map(_.trim))
      .getOrElse(request.remoteAddress)

  def encodeForUrl(value: String): String =
    java.net.URLEncoder.encode(value, "UTF-8")
