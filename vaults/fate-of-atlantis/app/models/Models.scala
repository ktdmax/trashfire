package models

import slick.jdbc.PostgresProfile.api.*
import java.time.{Instant, LocalDateTime}
import scala.collection.mutable
import play.api.libs.json.*

// ============================================================================
// Domain Models
// ============================================================================

case class User(
  id: Option[Long] = None,
  email: String,
  passwordHash: String,
  name: String,
  role: String = "researcher",
  institution: Option[String] = None,
  apiKey: Option[String] = None,
  createdAt: LocalDateTime = LocalDateTime.now(),
  lastLogin: Option[LocalDateTime] = None
)

case class Paper(
  id: Option[Long] = None,
  title: String,
  abstractText: Option[String] = None,
  authors: String,
  doi: Option[String] = None,
  year: Option[Int] = None,
  venue: Option[String] = None,
  filePath: Option[String] = None,
  uploadedBy: Long,
  metadata: Option[String] = None,
  rawXml: Option[String] = None,
  status: String = "draft",
  viewCount: Int = 0,
  createdAt: LocalDateTime = LocalDateTime.now(),
  updatedAt: LocalDateTime = LocalDateTime.now()
)

case class Citation(
  id: Option[Long] = None,
  sourcePaperId: Long,
  targetPaperId: Option[Long] = None,
  targetDoi: Option[String] = None,
  rawCitation: String,
  context: Option[String] = None,
  confidence: Double = 0.0
)

case class SearchLog(
  id: Option[Long] = None,
  userId: Option[Long] = None,
  query: String,
  resultsCount: Int,
  timestamp: LocalDateTime = LocalDateTime.now()
)

case class AuditEntry(
  id: Option[Long] = None,
  userId: Long,
  action: String,
  resource: String,
  details: String,
  ipAddress: String,
  timestamp: LocalDateTime = LocalDateTime.now()
)

// ============================================================================
// JSON Formats
// ============================================================================

object JsonFormats:
  // BUG-021: Exposing password hash and API key in JSON serialization (CWE-200, CVSS 7.5, HIGH, Tier 2)
  given userFormat: Format[User] = Json.format[User]
  given paperFormat: Format[Paper] = Json.format[Paper]
  given citationFormat: Format[Citation] = Json.format[Citation]
  given searchLogFormat: Format[SearchLog] = Json.format[SearchLog]
  given auditFormat: Format[AuditEntry] = Json.format[AuditEntry]

  // BUG-022: Custom reads trusts client-supplied role field (CWE-915, CVSS 8.1, HIGH, Tier 2)
  given userRegistrationReads: Reads[User] = Json.reads[User]

// ============================================================================
// Slick Table Mappings
// ============================================================================

class UsersTable(tag: Tag) extends Table[User](tag, "users"):
  def id          = column[Long]("id", O.PrimaryKey, O.AutoInc)
  def email       = column[String]("email", O.Unique)
  def passwordHash = column[String]("password_hash")
  def name        = column[String]("name")
  def role        = column[String]("role", O.Default("researcher"))
  def institution = column[Option[String]]("institution")
  def apiKey      = column[Option[String]]("api_key")
  def createdAt   = column[LocalDateTime]("created_at")
  def lastLogin   = column[Option[LocalDateTime]]("last_login")

  def * = (id.?, email, passwordHash, name, role, institution, apiKey, createdAt, lastLogin)
    .mapTo[User]

class PapersTable(tag: Tag) extends Table[Paper](tag, "papers"):
  def id          = column[Long]("id", O.PrimaryKey, O.AutoInc)
  def title       = column[String]("title")
  def abstractText = column[Option[String]]("abstract_text")
  def authors     = column[String]("authors")
  def doi         = column[Option[String]]("doi")
  def year        = column[Option[Int]]("year")
  def venue       = column[Option[String]]("venue")
  def filePath    = column[Option[String]]("file_path")
  def uploadedBy  = column[Long]("uploaded_by")
  def metadata    = column[Option[String]]("metadata")
  def rawXml      = column[Option[String]]("raw_xml")
  def status      = column[String]("status", O.Default("draft"))
  def viewCount   = column[Int]("view_count", O.Default(0))
  def createdAt   = column[LocalDateTime]("created_at")
  def updatedAt   = column[LocalDateTime]("updated_at")

  def * = (id.?, title, abstractText, authors, doi, year, venue, filePath,
           uploadedBy, metadata, rawXml, status, viewCount, createdAt, updatedAt)
    .mapTo[Paper]

  def uploaderFk = foreignKey("fk_paper_uploader", uploadedBy, TableQuery[UsersTable])(_.id)

class CitationsTable(tag: Tag) extends Table[Citation](tag, "citations"):
  def id             = column[Long]("id", O.PrimaryKey, O.AutoInc)
  def sourcePaperId  = column[Long]("source_paper_id")
  def targetPaperId  = column[Option[Long]]("target_paper_id")
  def targetDoi      = column[Option[String]]("target_doi")
  def rawCitation    = column[String]("raw_citation")
  def context        = column[Option[String]]("context")
  def confidence     = column[Double]("confidence", O.Default(0.0))

  def * = (id.?, sourcePaperId, targetPaperId, targetDoi, rawCitation, context, confidence)
    .mapTo[Citation]

  def sourceFk = foreignKey("fk_citation_source", sourcePaperId, TableQuery[PapersTable])(_.id)
  def targetFk = foreignKey("fk_citation_target", targetPaperId, TableQuery[PapersTable])(_.id.?)

class SearchLogsTable(tag: Tag) extends Table[SearchLog](tag, "search_logs"):
  def id           = column[Long]("id", O.PrimaryKey, O.AutoInc)
  def userId       = column[Option[Long]]("user_id")
  def query        = column[String]("query")
  def resultsCount = column[Int]("results_count")
  def timestamp    = column[LocalDateTime]("timestamp")

  def * = (id.?, userId, query, resultsCount, timestamp).mapTo[SearchLog]

class AuditTable(tag: Tag) extends Table[AuditEntry](tag, "audit_log"):
  def id        = column[Long]("id", O.PrimaryKey, O.AutoInc)
  def userId    = column[Long]("user_id")
  def action    = column[String]("action")
  def resource  = column[String]("resource")
  def details   = column[String]("details")
  def ipAddress = column[String]("ip_address")
  def timestamp = column[LocalDateTime]("timestamp")

  def * = (id.?, userId, action, resource, details, ipAddress, timestamp).mapTo[AuditEntry]

// ============================================================================
// In-Memory Caches (shared mutable state)
// ============================================================================

// BUG-023: Mutable global state with no synchronization - race conditions (CWE-362, CVSS 5.9, TRICKY, Tier 5)
object PaperCache:
  val cache: mutable.HashMap[Long, Paper] = mutable.HashMap.empty
  var lastRefresh: Long = 0L

  def get(id: Long): Option[Paper] = cache.get(id)

  def put(paper: Paper): Unit =
    paper.id.foreach(id => cache.put(id, paper))

  def invalidate(id: Long): Unit = cache.remove(id)

  def refresh(papers: Seq[Paper]): Unit =
    cache.clear()
    papers.foreach(p => p.id.foreach(id => cache.put(id, p)))
    lastRefresh = System.currentTimeMillis()

// BUG-024: Session store uses mutable HashMap with no TTL or size limit (CWE-400, CVSS 5.3, BEST_PRACTICE, Tier 5)
object SessionStore:
  val sessions: mutable.HashMap[String, (Long, Instant)] = mutable.HashMap.empty

  def create(token: String, userId: Long): Unit =
    sessions.put(token, (userId, Instant.now()))

  def validate(token: String): Option[Long] =
    sessions.get(token).map(_._1)

  def remove(token: String): Unit = sessions.remove(token)

// ============================================================================
// Akka Messages
// ============================================================================

// BUG-025: Messages extend Serializable enabling Java deserialization attacks (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
sealed trait PaperMessage extends java.io.Serializable
case class IndexPaper(paper: Paper) extends PaperMessage
case class RemovePaper(id: Long) extends PaperMessage
case class ReindexAll() extends PaperMessage
// BUG-026: Command message accepts arbitrary class name for reflection (CWE-470, CVSS 9.8, CRITICAL, Tier 1)
case class ExecuteTask(className: String, args: Map[String, String]) extends PaperMessage
case class ProcessUpload(paperId: Long, filePath: String, callback: String) extends PaperMessage
