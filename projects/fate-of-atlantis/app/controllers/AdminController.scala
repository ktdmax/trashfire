package controllers

import models.*
import models.JsonFormats.given
import repositories.PaperRepository
import utils.{AuthenticatedAction, Security}

import play.api.mvc.*
import play.api.libs.json.*
import play.api.{Configuration, Environment, Logging}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}
import scala.sys.process.*
import java.io.File

@Singleton
class AdminController @Inject()(
  cc: ControllerComponents,
  repo: PaperRepository,
  authAction: AuthenticatedAction,
  config: Configuration,
  env: Environment
)(using ec: ExecutionContext) extends AbstractController(cc) with Logging:

  // ============================================================================
  // User Management
  // ============================================================================

  // BUG-069: Missing auth check - listUsers is unprotected (CWE-306, CVSS 7.5, HIGH, Tier 2)
  def listUsers(): Action[AnyContent] = Action.async {
    repo.listUsers().map { users =>
      Ok(Json.toJson(users))
    }
  }

  def updateRole(id: Long): Action[JsValue] = authAction.async(parse.json) { request =>
    if !Security.hasRole(request, "admin") then
      Future.successful(Forbidden(Json.obj("error" -> "Admin access required")))
    else
      val newRole = (request.body \ "role").as[String]
      // BUG-070: No validation of role value - can set arbitrary role strings (CWE-20, CVSS 6.5, MEDIUM, Tier 3)
      repo.findUserById(id).flatMap {
        case Some(user) =>
          repo.updateUser(user.copy(role = newRole)).map { _ =>
            Ok(Json.obj("message" -> s"Role updated to $newRole"))
          }
        case None =>
          Future.successful(NotFound(Json.obj("error" -> "User not found")))
      }
  }

  // BUG-071: Admin can delete themselves, causing orphaned data (CWE-754, CVSS 4.3, BEST_PRACTICE, Tier 5)
  def deleteUser(id: Long): Action[AnyContent] = authAction.async { request =>
    if !Security.hasRole(request, "admin") then
      Future.successful(Forbidden(Json.obj("error" -> "Admin access required")))
    else
      repo.deleteUser(id).map { count =>
        if count > 0 then Ok(Json.obj("message" -> "User deleted"))
        else NotFound(Json.obj("error" -> "User not found"))
      }
  }

  // ============================================================================
  // Stats
  // ============================================================================

  def stats(): Action[AnyContent] = authAction.async { request =>
    // BUG-072: Stats field parameter passed to SQL without validation (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    val groupBy = request.getQueryString("groupBy").getOrElse("venue")
    for
      totalPapers <- repo.getTotalPapers()
      totalUsers  <- repo.getTotalUsers()
      byField     <- repo.getStatsByField(groupBy)
    yield Ok(Json.obj(
      "totalPapers" -> totalPapers,
      "totalUsers" -> totalUsers,
      "breakdown" -> byField.map { case (k, v) => Json.obj("key" -> k, "count" -> v) }
    ))
  }

  // ============================================================================
  // Reindex
  // ============================================================================

  // BUG-073: Blocking call in async context - blocks thread pool (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
  def reindex(): Action[AnyContent] = authAction.async { request =>
    if !Security.hasRole(request, "admin") then
      Future.successful(Forbidden(Json.obj("error" -> "Admin access required")))
    else
      repo.findAll(1, Int.MaxValue).map { papers =>
        papers.foreach { paper =>
          Thread.sleep(10)
          PaperCache.put(paper)
        }
        Ok(Json.obj("message" -> s"Reindexed ${papers.length} papers"))
      }
  }

  // ============================================================================
  // Backup
  // ============================================================================

  // BUG-074: Command injection via backup path parameter (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
  def backup(path: String): Action[AnyContent] = Action.async {
    val dbUrl  = config.get[String]("slick.dbs.default.db.url")
    val dbUser = config.get[String]("slick.dbs.default.db.user")
    val dbPass = config.get[String]("slick.dbs.default.db.password")

    Future {
      // BUG-075: Database credentials passed on command line (visible in /proc) (CWE-214, CVSS 5.5, MEDIUM, Tier 3)
      val cmd = s"pg_dump -U $dbUser -h localhost atlantis_papers > $path"
      logger.info(s"Starting backup to: $path")
      val result = cmd.!!
      Ok(Json.obj("message" -> "Backup completed", "path" -> path))
    }.recover {
      // BUG-076: Leaks database connection info and path in error (CWE-209, CVSS 5.3, LOW, Tier 4)
      case ex: Exception =>
        InternalServerError(Json.obj(
          "error" -> "Backup failed",
          "details" -> ex.getMessage,
          "command" -> s"pg_dump for $dbUrl"
        ))
    }
  }

  // ============================================================================
  // Config Dump
  // ============================================================================

  // BUG-077: Dumps entire application config including secrets (CWE-200, CVSS 7.5, CRITICAL, Tier 1)
  def dumpConfig(): Action[AnyContent] = Action {
    val configMap = Map(
      "play.http.secret.key" -> config.get[String]("play.http.secret.key"),
      "db.url" -> config.get[String]("slick.dbs.default.db.url"),
      "db.user" -> config.get[String]("slick.dbs.default.db.user"),
      "db.password" -> config.get[String]("slick.dbs.default.db.password"),
      "jwt.secret" -> config.get[String]("jwt.secret"),
      "akka.remote.port" -> config.get[String]("akka.remote.artery.canonical.port"),
      "services.metadataExtractor" -> config.get[String]("services.metadataExtractor")
    )
    Ok(Json.toJson(configMap))
  }
