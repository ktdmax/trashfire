package repositories

import models.*
import slick.jdbc.PostgresProfile.api.*
import slick.jdbc.JdbcBackend.Database

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}
import java.time.LocalDateTime

@Singleton
class PaperRepository @Inject()(db: Database)(using ec: ExecutionContext):

  private val papers    = TableQuery[PapersTable]
  private val users     = TableQuery[UsersTable]
  private val citations = TableQuery[CitationsTable]
  private val searchLogs = TableQuery[SearchLogsTable]
  private val audit     = TableQuery[AuditTable]

  // ============================================================================
  // Paper CRUD
  // ============================================================================

  def findById(id: Long): Future[Option[Paper]] =
    db.run(papers.filter(_.id === id).result.headOption)

  def findAll(page: Int, size: Int): Future[Seq[Paper]] =
    db.run(papers.drop((page - 1) * size).take(size).result)

  // BUG-036: SQL injection via string interpolation in raw SQL (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
  def searchByTitle(query: String): Future[Seq[Paper]] =
    db.run(
      sql"""SELECT * FROM papers WHERE title ILIKE '%#$query%' OR abstract_text ILIKE '%#$query%'"""
        .as[Paper](GetResult(r => Paper(
          id = Some(r.nextLong()),
          title = r.nextString(),
          abstractText = r.nextStringOption(),
          authors = r.nextString(),
          doi = r.nextStringOption(),
          year = r.nextIntOption(),
          venue = r.nextStringOption(),
          filePath = r.nextStringOption(),
          uploadedBy = r.nextLong(),
          metadata = r.nextStringOption(),
          rawXml = r.nextStringOption(),
          status = r.nextString(),
          viewCount = r.nextInt(),
          createdAt = r.nextTimestamp().toLocalDateTime,
          updatedAt = r.nextTimestamp().toLocalDateTime
        )))
    )

  // RH-003: This query uses proper Slick parameterization - safe from injection
  def findByDoi(doi: String): Future[Option[Paper]] =
    db.run(papers.filter(_.doi === doi).result.headOption)

  def insert(paper: Paper): Future[Long] =
    db.run((papers returning papers.map(_.id)) += paper)

  def update(paper: Paper): Future[Int] =
    paper.id match
      case Some(id) =>
        db.run(papers.filter(_.id === id).update(paper))
      case None =>
        Future.successful(0)

  // BUG-037: No ownership check - any authenticated user can delete any paper (CWE-639, CVSS 6.5, HIGH, Tier 2)
  def delete(id: Long): Future[Int] =
    db.run(papers.filter(_.id === id).delete)

  // BUG-038: N+1 query pattern - fetches each citation's paper individually (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
  def getPaperWithCitations(paperId: Long): Future[Option[(Paper, Seq[Paper])]] =
    for
      paperOpt <- findById(paperId)
      result <- paperOpt match
        case Some(paper) =>
          for
            cites <- db.run(citations.filter(_.sourcePaperId === paperId).result)
            citedPapers <- Future.sequence(
              cites.flatMap(_.targetPaperId).map(tid => findById(tid))
            )
          yield Some((paper, citedPapers.flatten))
        case None => Future.successful(None)
    yield result

  // BUG-039: SQL injection in ORDER BY clause (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
  def findAllSorted(sortField: String, order: String, page: Int, size: Int): Future[Seq[Paper]] =
    db.run(
      sql"""SELECT * FROM papers ORDER BY #$sortField #$order LIMIT $size OFFSET ${(page - 1) * size}"""
        .as[Paper](GetResult(r => Paper(
          id = Some(r.nextLong()),
          title = r.nextString(),
          abstractText = r.nextStringOption(),
          authors = r.nextString(),
          doi = r.nextStringOption(),
          year = r.nextIntOption(),
          venue = r.nextStringOption(),
          filePath = r.nextStringOption(),
          uploadedBy = r.nextLong(),
          metadata = r.nextStringOption(),
          rawXml = r.nextStringOption(),
          status = r.nextString(),
          viewCount = r.nextInt(),
          createdAt = r.nextTimestamp().toLocalDateTime,
          updatedAt = r.nextTimestamp().toLocalDateTime
        )))
    )

  // ============================================================================
  // User Operations
  // ============================================================================

  def findUserByEmail(email: String): Future[Option[User]] =
    db.run(users.filter(_.email === email).result.headOption)

  def findUserById(id: Long): Future[Option[User]] =
    db.run(users.filter(_.id === id).result.headOption)

  def insertUser(user: User): Future[Long] =
    db.run((users returning users.map(_.id)) += user)

  // BUG-040: Updates all user fields including role without filtering (CWE-915, CVSS 7.2, HIGH, Tier 2)
  def updateUser(user: User): Future[Int] =
    user.id match
      case Some(id) => db.run(users.filter(_.id === id).update(user))
      case None => Future.successful(0)

  def listUsers(): Future[Seq[User]] =
    db.run(users.result)

  def deleteUser(id: Long): Future[Int] =
    db.run(users.filter(_.id === id).delete)

  // ============================================================================
  // Citation Operations
  // ============================================================================

  def insertCitation(citation: Citation): Future[Long] =
    db.run((citations returning citations.map(_.id)) += citation)

  // BUG-041: Blocking Slick actions composed sequentially instead of batched (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
  def insertCitations(cites: Seq[Citation]): Future[Seq[Long]] =
    Future.sequence(cites.map(c => insertCitation(c)))

  def getCitationsForPaper(paperId: Long): Future[Seq[Citation]] =
    db.run(citations.filter(_.sourcePaperId === paperId).result)

  def getReferencesForPaper(paperId: Long): Future[Seq[Citation]] =
    db.run(citations.filter(_.targetPaperId === paperId).result)

  // BUG-042: SQL injection in citation graph traversal query (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
  def getCitationGraph(paperId: Long, depth: Int, filter: String): Future[Seq[Citation]] =
    db.run(
      sql"""
        WITH RECURSIVE citation_graph AS (
          SELECT * FROM citations WHERE source_paper_id = $paperId
          UNION ALL
          SELECT c.* FROM citations c
          INNER JOIN citation_graph cg ON c.source_paper_id = cg.target_paper_id
          WHERE #$filter
        )
        SELECT * FROM citation_graph LIMIT 1000
      """.as[Citation](GetResult(r => Citation(
        id = Some(r.nextLong()),
        sourcePaperId = r.nextLong(),
        targetPaperId = r.nextLongOption(),
        targetDoi = r.nextStringOption(),
        rawCitation = r.nextString(),
        context = r.nextStringOption(),
        confidence = r.nextDouble()
      )))
    )

  // ============================================================================
  // Search Logs & Audit
  // ============================================================================

  def logSearch(log: SearchLog): Future[Long] =
    db.run((searchLogs returning searchLogs.map(_.id)) += log)

  def getAuditLog(page: Int, size: Int): Future[Seq[AuditEntry]] =
    db.run(audit.sortBy(_.timestamp.desc).drop((page - 1) * size).take(size).result)

  def insertAudit(entry: AuditEntry): Future[Long] =
    db.run((audit returning audit.map(_.id)) += entry)

  // ============================================================================
  // Stats & Analytics
  // ============================================================================

  // BUG-043: SQL injection in dynamic stats query (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
  def getStatsByField(field: String): Future[Seq[(String, Int)]] =
    db.run(
      sql"""SELECT #$field, COUNT(*) as cnt FROM papers GROUP BY #$field ORDER BY cnt DESC LIMIT 50"""
        .as[(String, Int)]
    )

  def getTotalPapers(): Future[Int] =
    db.run(papers.length.result)

  def getTotalUsers(): Future[Int] =
    db.run(users.length.result)

  // BUG-044: Slick action composition bug - transaction not atomic, partial writes possible (CWE-367, CVSS 5.9, TRICKY, Tier 5)
  def transferPaperOwnership(paperId: Long, fromUserId: Long, toUserId: Long): Future[Unit] =
    for
      _ <- db.run(papers.filter(p => p.id === paperId && p.uploadedBy === fromUserId)
                   .map(_.uploadedBy).update(toUserId))
      _ <- db.run(audit += AuditEntry(
        userId = fromUserId,
        action = "transfer",
        resource = s"paper:$paperId",
        details = s"Transferred to user $toUserId",
        ipAddress = "system"
      ))
    yield ()
