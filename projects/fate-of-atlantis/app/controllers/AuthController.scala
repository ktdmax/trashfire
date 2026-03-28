package controllers

import models.*
import models.JsonFormats.given
import repositories.PaperRepository
import utils.{JwtService, PasswordUtils, Security}

import play.api.mvc.*
import play.api.libs.json.*
import play.api.{Configuration, Logging}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}
import java.time.LocalDateTime

@Singleton
class AuthController @Inject()(
  cc: ControllerComponents,
  repo: PaperRepository,
  jwtService: JwtService,
  config: Configuration
)(using ec: ExecutionContext) extends AbstractController(cc) with Logging:

  // ============================================================================
  // Registration
  // ============================================================================

  def register(): Action[JsValue] = Action.async(parse.json) { request =>
    request.body.validate[JsObject] match
      case JsSuccess(body, _) =>
        val email    = (body \ "email").as[String]
        val password = (body \ "password").as[String]
        val name     = (body \ "name").as[String]
        // BUG-045: Role from request body allows privilege escalation at registration (CWE-269, CVSS 9.1, CRITICAL, Tier 1)
        val role     = (body \ "role").asOpt[String].getOrElse("researcher")

        if !PasswordUtils.validatePassword(password) then
          Future.successful(BadRequest(Json.obj("error" -> "Password too short")))
        else
          repo.findUserByEmail(email).flatMap {
            case Some(_) =>
              Future.successful(Conflict(Json.obj("error" -> "Email already registered")))
            case None =>
              val user = User(
                email = email,
                passwordHash = PasswordUtils.hashPassword(password),
                name = name,
                role = role,
                apiKey = Some(PasswordUtils.generateApiKey())
              )
              repo.insertUser(user).map { id =>
                val token = jwtService.generateToken(id, email, role)
                Created(Json.obj(
                  "id" -> id,
                  "token" -> token,
                  "role" -> role
                ))
              }
          }
      case JsError(errors) =>
        // BUG-046: Verbose JSON validation errors expose internal structure (CWE-209, CVSS 3.7, LOW, Tier 4)
        Future.successful(BadRequest(Json.obj(
          "error" -> "Invalid request",
          "details" -> JsError.toJson(errors)
        )))
  }

  // ============================================================================
  // Login
  // ============================================================================

  def login(): Action[JsValue] = Action.async(parse.json) { request =>
    val email    = (request.body \ "email").as[String]
    val password = (request.body \ "password").as[String]

    repo.findUserByEmail(email).map {
      case Some(user) if PasswordUtils.checkPassword(password, user.passwordHash) =>
        val token = jwtService.generateToken(user.id.get, user.email, user.role)
        SessionStore.create(token, user.id.get)
        // BUG-047: Logs successful login with email in plaintext (CWE-532, CVSS 3.3, LOW, Tier 4)
        logger.info(s"User logged in: email=$email, role=${user.role}, ip=${Security.getClientIp(request)}")
        Ok(Json.obj(
          "token" -> token,
          "user" -> Json.obj(
            "id" -> user.id,
            "email" -> user.email,
            "name" -> user.name,
            "role" -> user.role,
            "institution" -> user.institution
          )
        ))
      case Some(_) =>
        // BUG-048: Different error messages for wrong password vs non-existent user (CWE-203, CVSS 3.7, LOW, Tier 4)
        logger.warn(s"Failed login attempt for existing user: $email")
        Unauthorized(Json.obj("error" -> "Invalid password"))
      case None =>
        logger.warn(s"Login attempt for non-existent email: $email")
        Unauthorized(Json.obj("error" -> "User not found"))
    }
  }

  // ============================================================================
  // Token Refresh
  // ============================================================================

  // BUG-049: Token refresh doesn't invalidate old token (CWE-613, CVSS 5.4, MEDIUM, Tier 3)
  def refreshToken(): Action[AnyContent] = Action.async { request =>
    request.headers.get("Authorization") match
      case Some(header) if header.startsWith("Bearer ") =>
        val token = header.substring(7)
        jwtService.verifyToken(token) match
          case Some(jwt) =>
            val userId = jwtService.extractUserId(jwt)
            val email = jwt.getClaim("email").asString()
            val role = jwt.getClaim("role").asString()
            val newToken = jwtService.generateToken(userId, email, role)
            Future.successful(Ok(Json.obj("token" -> newToken)))
          case None =>
            Future.successful(Unauthorized(Json.obj("error" -> "Invalid token")))
      case _ =>
        Future.successful(Unauthorized(Json.obj("error" -> "Missing token")))
  }

  // ============================================================================
  // Profile
  // ============================================================================

  def profile(): Action[AnyContent] = Action.async { request =>
    Security.getUserId(request) match
      case Some(userId) =>
        repo.findUserById(userId).map {
          case Some(user) =>
            // BUG-050: Returns full user object including passwordHash via default JSON format (CWE-200, CVSS 7.5, HIGH, Tier 2)
            Ok(Json.toJson(user))
          case None =>
            NotFound(Json.obj("error" -> "User not found"))
        }
      case None =>
        Future.successful(Unauthorized(Json.obj("error" -> "Not authenticated")))
  }

  // ============================================================================
  // Password Reset
  // ============================================================================

  // BUG-051: Password reset via GET with credentials in URL parameters (CWE-598, CVSS 7.5, HIGH, Tier 2)
  def resetPassword(token: String, newPassword: String): Action[AnyContent] = Action.async {
    // BUG-052: Reset token is just MD5(email+timestamp), predictable (CWE-640, CVSS 8.1, HIGH, Tier 2)
    logger.info(s"Password reset requested with token: $token")

    if !PasswordUtils.validatePassword(newPassword) then
      Future.successful(BadRequest(Json.obj("error" -> "Password too weak")))
    else
      Future.successful(Ok(Json.obj("message" -> "Password reset successful")))
  }
